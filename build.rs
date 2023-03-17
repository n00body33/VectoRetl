use std::{collections::HashSet, env, fs::File, io::Write, path::Path, process::Command};

struct TrackedEnv {
    tracked: HashSet<String>,
}

impl TrackedEnv {
    pub fn new() -> Self {
        Self {
            tracked: HashSet::new(),
        }
    }

    pub fn get_env_var(&mut self, name: impl Into<String>) -> Option<String> {
        let name = name.into();
        let result = std::env::var(&name).ok();
        self.tracked.insert(name);
        result
    }

    pub fn emit_rerun_stanzas(&self) {
        for env_var in &self.tracked {
            println!("cargo:rerun-if-env-changed={}", env_var);
        }
    }
}

enum ConstantValue {
    Required(String),
    Optional(Option<String>),
}

impl ConstantValue {
    pub fn as_parts(&self) -> (&'static str, String) {
        match &self {
            ConstantValue::Required(value) => ("&str", format!("\"{}\"", value)),
            ConstantValue::Optional(value) => match value {
                Some(value) => ("Option<&str>", format!("Some(\"{}\")", value)),
                None => ("Option<&str>", "None".to_string()),
            },
        }
    }
}

struct BuildConstants {
    values: Vec<(String, String, ConstantValue)>,
}

impl BuildConstants {
    pub fn new() -> Self {
        Self { values: Vec::new() }
    }

    pub fn add_required_constant(&mut self, name: &str, desc: &str, value: String) {
        self.values.push((
            name.to_string(),
            desc.to_string(),
            ConstantValue::Required(value),
        ));
    }

    pub fn add_optional_constant(&mut self, name: &str, desc: &str, value: Option<String>) {
        self.values.push((
            name.to_string(),
            desc.to_string(),
            ConstantValue::Optional(value),
        ));
    }

    pub fn write_to_file(self, file_name: impl AsRef<Path>) -> std::io::Result<()> {
        let base_dir = env::var("OUT_DIR").expect("OUT_DIR not present in build script!");
        let dest_path = Path::new(&base_dir).join(file_name);

        let mut output_file = File::create(dest_path)?;
        output_file.write_all(
            "// AUTOGENERATED CONSTANTS. SEE BUILD.RS AT REPOSITORY ROOT. DO NOT MODIFY.\n"
                .as_ref(),
        )?;

        for (name, desc, value) in self.values {
            let (const_type, const_val) = value.as_parts();
            let full = format!(
                "#[doc=r#\"{}\"#]\npub const {}: {} = {};\n",
                desc, name, const_type, const_val
            );
            output_file.write_all(full.as_ref())?;
        }

        output_file.flush()?;
        output_file.sync_all()?;

        Ok(())
    }
}

fn git_short_hash() -> std::io::Result<String> {
    let output_result = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output();

    output_result.map(|output| {
        let mut hash = String::from_utf8(output.stdout).unwrap();

        hash.retain(|c| c != '\n');
        hash.retain(|c| c != '\r');

        hash
    })
}

fn main() {
    // Always rerun if the build script itself changes.
    println!("cargo:rerun-if-changed=build.rs");

    // re-run if the HEAD has changed. This is only necessary for non-release and nightly builds.
    #[cfg(not(feature = "nightly"))]
    println!("cargo:rerun-if-changed=.git/HEAD");

    #[cfg(feature = "protobuf-build")]
    {
        println!("cargo:rerun-if-changed=proto/dd_trace.proto");
        println!("cargo:rerun-if-changed=proto/dnstap.proto");
        println!("cargo:rerun-if-changed=proto/ddsketch_full.proto");
        println!("cargo:rerun-if-changed=proto/dd_metric.proto");
        println!("cargo:rerun-if-changed=proto/google/pubsub/v1/pubsub.proto");
        println!("cargo:rerun-if-changed=proto/google/rpc/status.proto");
        println!("cargo:rerun-if-changed=proto/vector.proto");

        let mut prost_build = prost_build::Config::new();
        prost_build.btree_map(["."]);

        tonic_build::configure()
            .protoc_arg("--experimental_allow_proto3_optional")
            .compile_with_config(
                prost_build,
                &[
                    "lib/vector-core/proto/event.proto",
                    "proto/dnstap.proto",
                    "proto/ddsketch_full.proto",
                    "proto/dd_metric.proto",
                    "proto/dd_trace.proto",
                    "proto/google/pubsub/v1/pubsub.proto",
                    "proto/google/rpc/status.proto",
                    "proto/vector.proto",
                ],
                &["proto/", "lib/vector-core/proto/"],
            )
            .unwrap();
    }

    // We keep track of which environment variables we slurp in, and then emit stanzas at the end to
    // inform Cargo when it needs to rerun this build script.  This allows us to avoid rerunning it
    // every single time unless something _actually_ changes.
    let mut tracker = TrackedEnv::new();
    let pkg_name = tracker
        .get_env_var("CARGO_PKG_NAME")
        .expect("Cargo-provided environment variables should always exist!");
    let pkg_version = tracker
        .get_env_var("CARGO_PKG_VERSION")
        .expect("Cargo-provided environment variables should always exist!");
    let pkg_description = tracker
        .get_env_var("CARGO_PKG_DESCRIPTION")
        .expect("Cargo-provided environment variables should always exist!");
    let target = tracker
        .get_env_var("TARGET")
        .expect("Cargo-provided environment variables should always exist!");
    let target_arch = tracker
        .get_env_var("CARGO_CFG_TARGET_ARCH")
        .expect("Cargo-provided environment variables should always exist!");
    let target_os = tracker
        .get_env_var("CARGO_CFG_TARGET_OS")
        .expect("Cargo-provided environment variables should always exist!");
    let target_vendor = tracker
        .get_env_var("CARGO_CFG_TARGET_VENDOR")
        .expect("Cargo-provided environment variables should always exist!");
    let debug = tracker
        .get_env_var("DEBUG")
        .expect("Cargo-provided environment variables should always exist!");
    let rust_version = tracker
        .get_env_var("CARGO_PKG_RUST_VERSION")
        .expect("Cargo-provided environment variables should always exist!");
    let build_desc = tracker.get_env_var("VECTOR_BUILD_DESC");

    // Get the git short hash of the HEAD.
    // Note that if Vector is compiled within a container, proper git permissions must be set for
    // the repo directory.
    // In CI build workflows this will have been pre-configured by running the command
    // "git config --global --add safe.directory /git/vectordotdev/vector", from the vdev package
    // subcommands.
    let git_short_hash = git_short_hash()
        .map_err(|e| -> String {
            format!(
                "Unable to determine git short hash from rev-parse command: {}",
                e
            )
        })
        .unwrap();

    // Gather up the constants and write them out to our build constants file.
    let mut constants = BuildConstants::new();
    constants.add_required_constant(
        "RUST_VERSION",
        "The rust version from the package manifest.",
        rust_version,
    );
    constants.add_required_constant("PKG_NAME", "The full name of this package.", pkg_name);
    constants.add_required_constant(
        "PKG_VERSION",
        "The full version of this package.",
        pkg_version,
    );
    constants.add_required_constant(
        "PKG_DESCRIPTION",
        "The description of this package.",
        pkg_description,
    );
    constants.add_required_constant(
        "TARGET",
        "The target triple being compiled for. (e.g. x86_64-pc-windows-msvc)",
        target,
    );
    constants.add_required_constant(
        "TARGET_ARCH",
        "The target architecture being compiled for. (e.g. x86_64)",
        target_arch,
    );
    constants.add_required_constant(
        "TARGET_OS",
        "The target OS being compiled for. (e.g. macos)",
        target_os,
    );
    constants.add_required_constant(
        "TARGET_VENDOR",
        "The target vendor being compiled for. (e.g. apple)",
        target_vendor,
    );
    constants.add_required_constant("DEBUG", "Level of debug info for Vector.", debug);
    constants.add_optional_constant(
        "VECTOR_BUILD_DESC",
        "Special build description, related to versioned releases.",
        build_desc,
    );
    constants.add_required_constant(
        "GIT_SHORT_HASH",
        "The short hash of the Git HEAD",
        git_short_hash,
    );
    constants
        .write_to_file("built.rs")
        .expect("Failed to write build-time constants file!");

    // Emit the aforementioned stanzas.
    tracker.emit_rerun_stanzas();
}
