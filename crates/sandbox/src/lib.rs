//! Linux worker confinement. Call only in a freshly executed child before keys
//! or untrusted input are received. The caller must exit on any failure.

use std::fmt;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
mod preflight;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
mod policy;

#[cfg(all(
    test,
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
mod preflight_tests;

#[cfg(all(
    test,
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
mod policy_tests;

#[derive(Debug, Clone, Copy)]
pub struct WorkerLimits {
    /// Virtual address-space ceiling, not a physical-memory reservation.
    pub address_space_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxError {
    UnsupportedPlatform,
    InvalidLimits,
    InvalidProcess,
    InvalidDescriptors,
    ResourceLimit,
    PolicyInstall,
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Worker confinement rejected: {self:?}")
    }
}

impl std::error::Error for SandboxError {}

/// Restrict a freshly executed, single-threaded child before receiving keys.
///
/// The child must have an empty environment, stdin/stdout anonymous pipes and
/// only a pipe or `/dev/null` on stderr. All preconditions are checked before
/// irreversible changes. The caller must exit on **any** error: failure during
/// installation may leave some resource restrictions applied.
pub fn enter_worker(limits: WorkerLimits) -> Result<(), SandboxError> {
    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    {
        use rustix::process::{
            DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit,
        };

        preflight::check(limits)?;
        let program = policy::compile()?;
        let fixed_limit = |value| Rlimit {
            current: Some(value),
            maximum: Some(value),
        };
        setrlimit(Resource::Core, fixed_limit(0)).map_err(|_| SandboxError::ResourceLimit)?;
        set_dumpable_behavior(DumpableBehavior::NotDumpable)
            .map_err(|_| SandboxError::ResourceLimit)?;
        setrlimit(Resource::As, fixed_limit(limits.address_space_bytes))
            .map_err(|_| SandboxError::ResourceLimit)?;
        setrlimit(Resource::Nofile, fixed_limit(3)).map_err(|_| SandboxError::ResourceLimit)?;
        // TSYNC is defense in depth; a live second thread is rejected above.
        // The installer sets no-new-privileges and rejects nonzero TSYNC results.
        seccompiler::apply_filter_all_threads(&program).map_err(|_| SandboxError::PolicyInstall)
    }
    #[cfg(not(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    )))]
    {
        let _ = limits;
        Err(SandboxError::UnsupportedPlatform)
    }
}
