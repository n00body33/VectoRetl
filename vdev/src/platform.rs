use cached::proc_macro::once;
use directories::ProjectDirs;
use std::env::consts::ARCH;
use std::path::PathBuf;

#[once]
fn _os_info() -> os_info::Info {
    os_info::get()
}

#[once]
fn _project_dirs() -> Option<ProjectDirs> {
    ProjectDirs::from("", "vector", "vdev")
}

pub struct Platform {}

impl Platform {
    pub fn new() -> Platform {
        Platform {}
    }

    pub fn canonicalize_path(&self, path: &String) -> String {
        match dunce::canonicalize(path) {
            Ok(p) => p.display().to_string(),
            Err(_) => path.to_string(),
        }
    }

    pub fn home(&self) -> PathBuf {
        match home::home_dir() {
            Some(path) => path,
            None => ["~"].iter().collect(),
        }
    }

    pub fn data_dir(&self) -> PathBuf {
        match _project_dirs() {
            Some(path) => path.data_local_dir().to_path_buf(),
            None => [self.home().to_str().unwrap(), ".local", "vector", "vdev"]
                .iter()
                .collect(),
        }
    }

    pub fn default_target(&self) -> String {
        if self.windows() {
            format!("{}-pc-windows-msvc", ARCH)
        } else if self.macos() {
            format!("{}-apple-darwin", ARCH)
        } else {
            format!("{}-unknown-linux-gnu", ARCH)
        }
    }

    pub const fn windows(&self) -> bool {
        cfg!(target_os = "windows")
    }

    #[allow(dead_code)]
    pub const fn macos(&self) -> bool {
        cfg!(target_os = "macos")
    }

    #[allow(dead_code)]
    pub const fn unix(&self) -> bool {
        cfg!(not(any(target_os = "windows", target_os = "macos")))
    }

    #[allow(dead_code)]
    pub fn os_type(&self) -> os_info::Type {
        _os_info().os_type()
    }
}
