//! Linux test infrastructure. This crate is a dev-dependency of the product.
//! Owned child processes, bounded capture and group cleanup; not tenant confinement.

mod keys;
mod process;
pub mod runner;

pub use keys::{fixture_gateway_public, fixture_node_keys, fixture_projection, fixture_public};
pub use process::{CapturedOutput, ManagedChild, ProcessError, ProcessLimits, ProcessSpec};
