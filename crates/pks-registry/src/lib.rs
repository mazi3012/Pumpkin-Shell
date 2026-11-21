//! npm and PyPI registry guard (PRD FR-REG, Phase 14).
//!
//! The pure checks live here: package age and cooldown, checksums, names and
//! the typosquat list. They take the time as an argument and read no files and
//! no network, so every rule is tested with fixed inputs.

pub mod age;
pub mod document;
pub mod integrity;
pub mod mirror;
pub mod names;
pub mod server;
pub mod typosquat;
pub mod upstream;
