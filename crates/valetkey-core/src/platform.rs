//! The platform valetkey runs on. Several guarantees differ per platform (§2.7, §11).

/// An operating system family that valetkey distinguishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    Linux,
    Windows,
    Other,
}

impl Platform {
    /// The platform this binary was built for.
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(windows) {
            Self::Windows
        } else {
            Self::Other
        }
    }

    /// The longest unix socket path the platform accepts, in bytes (M0: Go's checks match the
    /// kernel's `sun_path` size minus the terminating NUL).
    pub fn max_socket_path_len(self) -> usize {
        match self {
            Self::MacOs => 103,
            _ => 107,
        }
    }
}
