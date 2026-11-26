//! Fixed Linux x86-64 policy; no caller-supplied syscall IDs or BPF.

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::SandboxError;

fn equal(
    index: u8,
    length: SeccompCmpArgLen,
    value: u64,
) -> Result<SeccompCondition, SandboxError> {
    SeccompCondition::new(index, length, SeccompCmpOp::Eq, value)
        .map_err(|_| SandboxError::PolicyInstall)
}

fn rule(conditions: Vec<SeccompCondition>) -> Result<SeccompRule, SandboxError> {
    SeccompRule::new(conditions).map_err(|_| SandboxError::PolicyInstall)
}

pub(super) fn compile() -> Result<BpfProgram, SandboxError> {
    use SeccompCmpArgLen::{Dword, Qword};
    let mut rules = BTreeMap::new();
    // Duplicate syscall entries must not silently overwrite a restriction.
    let mut add = |number, alternatives| {
        if rules.insert(number, alternatives).is_some() {
            Err(SandboxError::PolicyInstall)
        } else {
            Ok(())
        }
    };
    for (number, descriptor) in [(libc::SYS_read, 0), (libc::SYS_write, 1)] {
        add(number, vec![rule(vec![equal(0, Dword, descriptor)?])?])?;
    }
    add(
        libc::SYS_close,
        (0..=2)
            .map(|fd| rule(vec![equal(0, Dword, fd)?]))
            .collect::<Result<_, _>>()?,
    )?;
    for number in [
        libc::SYS_brk,
        libc::SYS_munmap,
        libc::SYS_rt_sigreturn,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        add(number, vec![])?;
    }
    // mmap's protection and flag arguments are unsigned long in the native
    // kernel ABI. Exact 64-bit comparisons reject unknown/high flag bits.
    add(
        libc::SYS_mmap,
        [libc::PROT_NONE, libc::PROT_READ | libc::PROT_WRITE]
            .into_iter()
            .map(|protection| {
                rule(vec![
                    equal(2, Qword, protection as u64)?,
                    equal(3, Qword, (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64)?,
                    equal(4, Dword, u32::MAX as u64)?,
                    equal(5, Qword, 0)?,
                ])
            })
            .collect::<Result<_, _>>()?,
    )?;
    // Preflight excludes every shared mapping and READ_IMPLIES_EXEC, so
    // mprotect cannot upgrade a shared mapping or implicitly add execution.
    add(
        libc::SYS_mprotect,
        [
            libc::PROT_NONE,
            libc::PROT_READ,
            libc::PROT_READ | libc::PROT_WRITE,
        ]
        .into_iter()
        .map(|protection| rule(vec![equal(2, Qword, protection as u64)?]))
        .collect::<Result<_, _>>()?,
    )?;
    add(
        libc::SYS_mremap,
        [0, libc::MREMAP_MAYMOVE]
            .into_iter()
            .map(|flags| rule(vec![equal(3, Qword, flags as u64)?]))
            .collect::<Result<_, _>>()?,
    )?;
    // glibc allocation release and AWS-LC's fork-generation page. No advice
    // that makes pages shareable (e.g. MERGEABLE) is permitted.
    add(
        libc::SYS_madvise,
        [libc::MADV_DONTNEED, libc::MADV_WIPEONFORK]
            .into_iter()
            .map(|advice| rule(vec![equal(2, Dword, advice as u64)?]))
            .collect::<Result<_, _>>()?,
    )?;
    // GotaTun's sleepyinstant explicitly requests BOOTTIME. vDSO availability
    // must not conceal a denied native-syscall fallback on another host.
    let clock_rules = [
        libc::CLOCK_REALTIME,
        libc::CLOCK_MONOTONIC,
        libc::CLOCK_BOOTTIME,
    ]
    .into_iter()
    .map(|clock| rule(vec![equal(0, Dword, clock as u64)?]))
    .collect::<Result<_, _>>()?;
    add(libc::SYS_clock_gettime, clock_rules)?;
    add(
        libc::SYS_clock_nanosleep,
        [libc::CLOCK_REALTIME, libc::CLOCK_MONOTONIC]
            .into_iter()
            .map(|clock| rule(vec![equal(0, Dword, clock as u64)?, equal(1, Dword, 0)?]))
            .collect::<Result<_, _>>()?,
    )?;
    add(libc::SYS_nanosleep, vec![])?;
    // Rust's HashMap seeding uses INSECURE; glibc's vDSO path additionally
    // sets NONBLOCK, which the vDSO syscall fallback preserves. Cryptographic
    // providers use blocking/nonblocking entropy. Do not permit GRND_RANDOM
    // or arbitrary combinations. Limit each request before entering the kernel.
    add(
        libc::SYS_getrandom,
        [
            0,
            libc::GRND_NONBLOCK,
            libc::GRND_INSECURE,
            libc::GRND_INSECURE | libc::GRND_NONBLOCK,
        ]
        .into_iter()
        .map(|flags| {
            rule(vec![
                equal(2, Dword, flags as u64)?,
                SeccompCondition::new(1, Qword, SeccompCmpOp::Le, 4096)
                    .map_err(|_| SandboxError::PolicyInstall)?,
            ])
        })
        .collect::<Result<_, _>>()?,
    )?;
    add(
        libc::SYS_futex,
        [
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            libc::FUTEX_WAIT_BITSET | libc::FUTEX_PRIVATE_FLAG,
            libc::FUTEX_WAIT_BITSET | libc::FUTEX_PRIVATE_FLAG | libc::FUTEX_CLOCK_REALTIME,
        ]
        .into_iter()
        .map(|operation| rule(vec![equal(1, Dword, operation as u64)?]))
        .collect::<Result<_, _>>()?,
    )?;

    let program: BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        TargetArch::x86_64,
    )
    .map_err(|_| SandboxError::PolicyInstall)?
    .try_into()
    .map_err(|_| SandboxError::PolicyInstall)?;
    // seccompiler's installer casts program length to u16. Retain our own
    // bound even though its compiler currently checks the kernel's limit.
    if program.is_empty() || program.len() >= 4096 {
        return Err(SandboxError::PolicyInstall);
    }
    Ok(program)
}
