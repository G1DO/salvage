//! The PostgreSQL adapter boundary.

/// Identifies the PostgreSQL adapter used by the bootstrap check.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Adapter;

impl Adapter {
    /// Creates the adapter boundary without connecting to a database.
    pub const fn new() -> Self {
        Self
    }

    /// Returns the stable adapter identifier used in machine-readable output.
    pub const fn name(self) -> &'static str {
        "postgres"
    }
}
