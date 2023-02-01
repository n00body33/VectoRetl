use std::collections::HashSet;
use std::process::{Command, Stdio};
use std::{env, ffi::OsStr, ffi::OsString, path::PathBuf};

use anyhow::Result;
use atty::Stream;
use once_cell::sync::Lazy;

use super::config::{Environment, IntegrationRunnerConfig, RustToolchainConfig};
use crate::app::{self, CommandExt as _};
use crate::util::ChainArgs as _;

const MOUNT_PATH: &str = "/home/vector";
const TARGET_PATH: &str = "/home/target";
const VOLUME_TARGET: &str = "vector_target";
const VOLUME_CARGO_GIT: &str = "vector_cargo_git";
const VOLUME_CARGO_REGISTRY: &str = "vector_cargo_registry";
const RUNNER_HOSTNAME: &str = "runner";
const TEST_COMMAND: &[&str] = &[
    "cargo",
    "nextest",
    "run",
    "--no-fail-fast",
    "--no-default-features",
];
// The upstream container we publish artifacts to on a successful master build.
const UPSTREAM_IMAGE: &str =
    "docker.io/timberio/vector-dev:sha-3eadc96742a33754a5859203b58249f6a806972a";

pub static CONTAINER_TOOL: Lazy<OsString> =
    Lazy::new(|| env::var_os("CONTAINER_TOOL").unwrap_or_else(detect_container_tool));

pub static DOCKER_SOCK: Lazy<PathBuf> = Lazy::new(detect_docker_sock);

fn detect_container_tool() -> OsString {
    for tool in ["docker", "podman"] {
        if Command::new(tool)
            .arg("version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .and_then(|mut child| child.wait())
            .map_or(false, |status| status.success())
        {
            return OsString::from(String::from(tool));
        }
    }
    fatal!("No container tool could be detected.");
}

fn dockercmd<I: AsRef<OsStr>>(args: impl IntoIterator<Item = I>) -> Command {
    let mut command = Command::new(&*CONTAINER_TOOL);
    command.args(args);
    command
}

pub enum RunnerState {
    Running,
    Restarting,
    Created,
    Exited,
    Paused,
    Dead,
    Missing,
    Unknown,
}

pub fn get_agent_test_runner(container: bool) -> Result<Box<dyn TestRunner>> {
    if container {
        Ok(Box::new(DockerTestRunner))
    } else {
        Ok(Box::new(LocalTestRunner))
    }
}

pub trait TestRunner {
    fn test(&self, outer_env: &Environment, inner_env: &Environment, args: &[String])
        -> Result<()>;
}

pub trait ContainerTestRunner: TestRunner {
    fn container_name(&self) -> String;

    fn image_name(&self) -> String;

    fn network_name(&self) -> Option<String>;

    fn needs_docker_sock(&self) -> bool;

    fn stop(&self) -> Result<()> {
        dockercmd(["stop", "--time", "0", &self.container_name()])
            .wait(format!("Stopping container {}", self.container_name()))
    }

    fn get_rust_version(&self) -> String {
        match RustToolchainConfig::parse() {
            Ok(config) => config.channel,
            Err(error) => fatal!("Could not read `rust-toolchain.toml` file: {error}"),
        }
    }

    fn state(&self) -> Result<RunnerState> {
        let mut command = dockercmd(["ps", "-a", "--format", "{{.Names}} {{.State}}"]);
        let container_name = self.container_name();

        for line in command.capture_output()?.lines() {
            if let Some((name, state)) = line.split_once(' ') {
                if name == container_name {
                    return Ok(if state == "created" {
                        RunnerState::Created
                    } else if state == "dead" {
                        RunnerState::Dead
                    } else if state == "exited" || state.starts_with("Exited ") {
                        RunnerState::Exited
                    } else if state == "paused" {
                        RunnerState::Paused
                    } else if state == "restarting" {
                        RunnerState::Restarting
                    } else if state == "running" || state.starts_with("Up ") {
                        RunnerState::Running
                    } else {
                        RunnerState::Unknown
                    });
                }
            }
        }

        Ok(RunnerState::Missing)
    }

    fn ensure_running(&self) -> Result<()> {
        match self.state()? {
            RunnerState::Running | RunnerState::Restarting => (),
            RunnerState::Created | RunnerState::Exited => self.start()?,
            RunnerState::Paused => self.unpause()?,
            RunnerState::Dead | RunnerState::Unknown => {
                self.remove()?;
                self.create()?;
                self.start()?;
            }
            RunnerState::Missing => {
                self.build()?;
                self.ensure_volumes()?;
                self.create()?;
                self.start()?;
            }
        }

        Ok(())
    }

    fn ensure_volumes(&self) -> Result<()> {
        let mut command = dockercmd(["volume", "ls", "--format", "{{.Name}}"]);

        let mut volumes = HashSet::new();
        volumes.insert(VOLUME_TARGET);
        volumes.insert(VOLUME_CARGO_GIT);
        volumes.insert(VOLUME_CARGO_REGISTRY);
        for volume in command.capture_output()?.lines() {
            volumes.take(volume);
        }

        for volume in &volumes {
            dockercmd(["volume", "create", volume]).wait(format!("Creating volume {volume}"))?;
        }

        Ok(())
    }

    fn build(&self) -> Result<()> {
        let dockerfile: PathBuf = [app::path(), "scripts", "integration", "Dockerfile"]
            .iter()
            .collect();
        let mut command = dockercmd(["build"]);
        command.current_dir(app::path());
        if atty::is(Stream::Stdout) {
            command.args(["--progress", "tty"]);
        }
        command.args([
            "--pull",
            "--tag",
            &self.image_name(),
            "--file",
            dockerfile.to_str().unwrap(),
            "--build-arg",
            &format!("RUST_VERSION={}", self.get_rust_version()),
            ".",
        ]);

        waiting!("Building image {}", self.image_name());
        command.check_run()
    }

    fn start(&self) -> Result<()> {
        dockercmd(["start", &self.container_name()])
            .wait(format!("Starting container {}", self.container_name()))
    }

    fn remove(&self) -> Result<()> {
        if matches!(self.state()?, RunnerState::Missing) {
            Ok(())
        } else {
            dockercmd(["rm", "--force", "--volumes", &self.container_name()])
                .wait(format!("Removing container {}", self.container_name()))
        }
    }

    fn unpause(&self) -> Result<()> {
        dockercmd(["unpause", &self.container_name()])
            .wait(format!("Unpausing container {}", self.container_name()))
    }

    fn create(&self) -> Result<()> {
        let network_name = self.network_name().unwrap_or_else(|| "host".into());
        let docker_sock = format!("{}:/var/run/docker.sock", DOCKER_SOCK.display());
        let docker_args = self
            .needs_docker_sock()
            .then(|| vec!["--volume", &docker_sock])
            .unwrap_or_default();
        dockercmd(
            [
                "create",
                "--name",
                &self.container_name(),
                "--network",
                &network_name,
                "--hostname",
                RUNNER_HOSTNAME,
                "--workdir",
                MOUNT_PATH,
                "--volume",
                &format!("{}:{MOUNT_PATH}", app::path()),
                "--volume",
                &format!("{VOLUME_TARGET}:{TARGET_PATH}"),
                "--volume",
                &format!("{VOLUME_CARGO_GIT}:/usr/local/cargo/git"),
                "--volume",
                &format!("{VOLUME_CARGO_REGISTRY}:/usr/local/cargo/registry"),
                "--volume",
                "/tmp:/tmp",
            ]
            .chain_args(docker_args)
            .chain_args([&self.image_name(), "/bin/sleep", "infinity"]),
        )
        .wait(format!("Creating container {}", self.container_name()))
    }
}

impl<T> TestRunner for T
where
    T: ContainerTestRunner,
{
    fn test(
        &self,
        outer_env: &Environment,
        inner_env: &Environment,
        args: &[String],
    ) -> Result<()> {
        self.ensure_running()?;

        let mut command = dockercmd(["exec"]);
        if atty::is(Stream::Stdout) {
            command.arg("--tty");
        }

        command.args(["--env", &format!("CARGO_BUILD_TARGET_DIR={TARGET_PATH}")]);
        for (key, value) in outer_env {
            if let Some(value) = value {
                command.env(key, value);
            }
            command.args(["--env", key]);
        }
        for (key, value) in inner_env {
            command.arg("--env");
            match value {
                Some(value) => command.arg(format!("{key}={value}")),
                None => command.arg(key),
            };
        }

        command.arg(&self.container_name());
        command.args(TEST_COMMAND);
        command.args(args);

        command.check_run()
    }
}

pub struct IntegrationTestRunner {
    integration: String,
    needs_docker_sock: bool,
    needs_network: bool,
}

impl IntegrationTestRunner {
    pub fn new(
        integration: String,
        config: &IntegrationRunnerConfig,
        needs_network: bool,
    ) -> Result<Self> {
        Ok(Self {
            integration,
            needs_docker_sock: config.needs_docker_sock,
            needs_network,
        })
    }

    pub(super) fn ensure_network(&self) -> Result<()> {
        if let Some(network_name) = self.network_name() {
            let mut command = dockercmd(["network", "ls", "--format", "{{.Name}}"]);

            if command
                .capture_output()?
                .lines()
                .any(|network| network == network_name)
            {
                return Ok(());
            }

            dockercmd(["network", "create", &network_name]).wait("Creating network")
        } else {
            Ok(())
        }
    }
}

impl ContainerTestRunner for IntegrationTestRunner {
    fn network_name(&self) -> Option<String> {
        self.needs_network
            .then(|| format!("vector-integration-tests-{}", self.integration))
    }

    fn container_name(&self) -> String {
        format!(
            "vector-test-runner-{}-{}",
            self.integration,
            self.get_rust_version()
        )
    }

    fn image_name(&self) -> String {
        format!("{}:latest", self.container_name())
    }

    fn needs_docker_sock(&self) -> bool {
        self.needs_docker_sock
    }
}

pub struct DockerTestRunner;

impl ContainerTestRunner for DockerTestRunner {
    fn network_name(&self) -> Option<String> {
        None
    }

    fn container_name(&self) -> String {
        format!("vector-test-runner-{}", self.get_rust_version())
    }

    fn image_name(&self) -> String {
        env::var("ENVIRONMENT_UPSTREAM").unwrap_or_else(|_| UPSTREAM_IMAGE.to_string())
    }

    fn needs_docker_sock(&self) -> bool {
        false
    }
}

pub struct LocalTestRunner;

impl TestRunner for LocalTestRunner {
    fn test(
        &self,
        outer_env: &Environment,
        inner_env: &Environment,
        args: &[String],
    ) -> Result<()> {
        let mut command = Command::new(TEST_COMMAND[0]);
        command.args(&TEST_COMMAND[1..]);
        command.args(args);

        for (key, value) in outer_env {
            if let Some(value) = value {
                command.env(key, value);
            }
        }
        for (key, value) in inner_env {
            if let Some(value) = value {
                command.env(key, value);
            }
        }

        command.check_run()
    }
}

fn detect_docker_sock() -> PathBuf {
    match env::var_os("DOCKER_HOST") {
        Some(host) => host
            .into_string()
            .expect("Invalid value in $DOCKER_HOST")
            .strip_prefix("unix://")
            .expect("$DOCKER_HOST is not a socket path")
            .into(),
        None => "/var/run/docker.sock".into(),
    }
}
