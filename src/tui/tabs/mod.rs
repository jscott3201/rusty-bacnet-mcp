//! Tab definitions and per-tab state.

pub mod configure;
pub mod observe;
pub mod operate;
pub mod shell;

/// Top-level tabs in the operator console.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Tab {
    Configure,
    Observe,
    Operate,
    Shell,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Configure, Tab::Observe, Tab::Operate, Tab::Shell];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Configure => "Configure",
            Tab::Observe => "Observe",
            Tab::Operate => "Operate",
            Tab::Shell => "Shell",
        }
    }

    pub fn index(self) -> usize {
        match self {
            Tab::Configure => 0,
            Tab::Observe => 1,
            Tab::Operate => 2,
            Tab::Shell => 3,
        }
    }

    pub fn next(self) -> Tab {
        Tab::ALL[(self.index() + 1) % Tab::ALL.len()]
    }

    pub fn prev(self) -> Tab {
        Tab::ALL[(self.index() + Tab::ALL.len() - 1) % Tab::ALL.len()]
    }
}
