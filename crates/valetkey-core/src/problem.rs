//! A validation problem, reported to a human by `allow` and `doctor`.

use std::fmt;

/// Something wrong with a config or its environment, optionally tied to a target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    pub target: Option<String>,
    pub message: String,
}

impl Problem {
    pub fn global(message: impl Into<String>) -> Self {
        Self {
            target: None,
            message: message.into(),
        }
    }

    pub fn target(target: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            target: Some(target.into()),
            message: message.into(),
        }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.target {
            Some(t) => write!(f, "{t}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}
