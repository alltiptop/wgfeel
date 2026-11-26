//! Expectations use the Linux x86-64 ABI, not the policy's rule map.
//! This interpreter never installs a filter or executes a syscall.

use seccompiler::BpfProgram;

const X86_64: u32 = 0xc000_003e;
const ALLOW: u32 = 0x7fff_0000;
const EPERM: u32 = 0x0005_0001;
const KILL_PROCESS: u32 = 0x8000_0000;

fn evaluate(program: &BpfProgram, number: u32, arch: u32, arguments: [u64; 6]) -> u32 {
    assert!(!program.is_empty() && program.len() < 4096);
    // struct seccomp_data: nr, arch, instruction_pointer, args[6]. Native
    // x86-64 is little-endian; pointers are deliberately unused by this policy.
    let mut data = [0_u8; 64];
    data[..4].copy_from_slice(&number.to_le_bytes());
    data[4..8].copy_from_slice(&arch.to_le_bytes());
    for (index, argument) in arguments.into_iter().enumerate() {
        data[16 + index * 8..24 + index * 8].copy_from_slice(&argument.to_le_bytes());
    }
    let mut accumulator = 0_u32;
    let mut pc = 0_usize;
    for _ in 0..4096 {
        let instruction = program.get(pc).expect("BPF jumps outside its program");
        let advance = match instruction.code {
            0x20 => {
                // BPF_LD | BPF_W | BPF_ABS.
                let offset = instruction.k as usize;
                assert_eq!(offset % 4, 0, "unaligned BPF input load");
                accumulator = u32::from_le_bytes(
                    data.get(offset..offset.checked_add(4).unwrap())
                        .expect("BPF reads outside seccomp_data")
                        .try_into()
                        .unwrap(),
                );
                1
            }
            0x05 => 1_usize.checked_add(instruction.k as usize).unwrap(), // JA.
            0x15 | 0x25 | 0x35 => {
                let matched = match instruction.code {
                    0x15 => accumulator == instruction.k, // JEQ.
                    0x25 => accumulator > instruction.k,  // JGT.
                    0x35 => accumulator >= instruction.k, // JGE.
                    _ => unreachable!(),
                };
                1 + usize::from(if matched {
                    instruction.jt
                } else {
                    instruction.jf
                })
            }
            0x06 => return instruction.k, // BPF_RET | BPF_K.
            opcode => panic!("unsupported BPF opcode: {opcode:#x}"),
        };
        pc = pc
            .checked_add(advance)
            .expect("BPF instruction offset overflow");
    }
    panic!("BPF exceeded its evaluation bound")
}

fn compiled() -> BpfProgram {
    super::policy::compile().expect("fixed policy compiles")
}

#[test]
fn only_the_int_width_stdin_and_stdout_descriptors_allow_data_io() {
    let program = compiled();
    for (number, permitted) in [(0, 0), (1, 1)] {
        for descriptor in [0, 1, 2, 3, u64::MAX] {
            let mut args = [0; 6];
            args[0] = descriptor;
            assert_eq!(
                evaluate(&program, number, X86_64, args),
                if descriptor == permitted {
                    ALLOW
                } else {
                    EPERM
                }
            );
        }
        // Native read/write take an unsigned-int descriptor: upper bits are
        // ignored by the kernel and cannot change fd 0/1 into another fd.
        let mut args = [0; 6];
        args[0] = (1 << 32) | permitted;
        assert_eq!(evaluate(&program, number, X86_64, args), ALLOW);
    }
    for descriptor in 0..=3 {
        assert_eq!(
            evaluate(&program, 3, X86_64, [descriptor, 0, 0, 0, 0, 0]),
            if descriptor < 3 { ALLOW } else { EPERM }
        );
    }
}

#[test]
fn native_mapping_arguments_reject_execution_sharing_files_and_high_bits() {
    let program = compiled();
    let allocation = [0, 4096, 3, 0x22, u64::MAX, 0];
    assert_eq!(evaluate(&program, 9, X86_64, allocation), ALLOW);
    let mut guard_page = allocation;
    guard_page[2] = 0;
    assert_eq!(evaluate(&program, 9, X86_64, guard_page), ALLOW);
    for (argument, value) in [
        (2, 4),
        (2, 7),
        (2, (1 << 32) | 3),
        (3, 0x21), // MAP_SHARED | MAP_ANONYMOUS.
        (3, 0x02), // File-backed MAP_PRIVATE.
        (3, 0x32), // MAP_FIXED additionally set.
        (3, (1 << 32) | 0x22),
        (4, 0),
        (5, 4096),
        (5, 1 << 32),
    ] {
        let mut args = allocation;
        args[argument] = value;
        assert_eq!(evaluate(&program, 9, X86_64, args), EPERM);
    }
    for protection in [0, 1, 3, 4, 5, 7, (1 << 32) | 1] {
        assert_eq!(
            evaluate(&program, 10, X86_64, [0, 4096, protection, 0, 0, 0]),
            if matches!(protection, 0 | 1 | 3) {
                ALLOW
            } else {
                EPERM
            }
        );
    }
    for flags in [0, 1, 3, 4, (1 << 32) | 1] {
        assert_eq!(
            evaluate(&program, 25, X86_64, [0, 4096, 8192, flags, 0, 0]),
            if flags <= 1 { ALLOW } else { EPERM }
        );
    }
}

#[test]
fn entropy_request_size_is_full_width_and_flags_are_restricted() {
    let program = compiled();
    for flags in [0, 1, 2, 3, 4, (1 << 32) | 1] {
        assert_eq!(
            evaluate(&program, 318, X86_64, [0, 4096, flags, 0, 0, 0]),
            if matches!(flags as u32, 0 | 1 | 4) {
                ALLOW
            } else {
                EPERM
            }
        );
    }
    for length in [4097, 1 << 32, u64::MAX] {
        assert_eq!(
            evaluate(&program, 318, X86_64, [0, length, 0, 0, 0, 0]),
            EPERM
        );
    }
}

#[test]
fn libc_insecure_nonblocking_entropy_fallback_is_permitted() {
    let program = compiled();
    // The reviewed glibc 2.44 vDSO path ORs GRND_NONBLOCK into Rust's
    // GRND_INSECURE request; its syscall fallback therefore receives 4 | 1.
    for flags in [5, (1 << 32) | 5] {
        assert_eq!(
            evaluate(&program, 318, X86_64, [0, 16, flags, 0, 0, 0]),
            ALLOW
        );
    }
}

#[test]
fn ordinary_clock_reads_and_relative_sleep_have_narrow_clock_ids() {
    let program = compiled();
    for clock in [0, 1] {
        assert_eq!(
            evaluate(&program, 228, X86_64, [clock, 0, 0, 0, 0, 0]),
            ALLOW
        );
        assert_eq!(
            evaluate(&program, 230, X86_64, [clock, 0, 0, 0, 0, 0]),
            ALLOW
        );
        assert_eq!(
            evaluate(&program, 230, X86_64, [clock, 1, 0, 0, 0, 0]),
            EPERM
        );
    }
    for clock in [2, 3, 4, 5, 6, u64::MAX] {
        assert_eq!(
            evaluate(&program, 228, X86_64, [clock, 0, 0, 0, 0, 0]),
            EPERM
        );
    }
    assert_eq!(evaluate(&program, 230, X86_64, [7, 0, 0, 0, 0, 0]), EPERM);
}

#[test]
fn gotatun_boottime_syscall_fallback_is_permitted_without_vdso() {
    let program = compiled();
    // GotaTun 0.10.3 sleepyinstant/unix.rs uses CLOCK_BOOTTIME (7), even
    // though a successful live run may have serviced it entirely in vDSO.
    assert_eq!(evaluate(&program, 228, X86_64, [7, 0, 0, 0, 0, 0]), ALLOW);
    assert_eq!(
        evaluate(&program, 228, X86_64, [(1 << 32) | 7, 0, 0, 0, 0, 0]),
        ALLOW
    );
}

#[test]
fn futex_operations_require_private_wait_or_wake() {
    let program = compiled();
    for operation in [128, 129, 137, 393] {
        assert_eq!(
            evaluate(&program, 202, X86_64, [0, operation, 0, 0, 0, 0]),
            ALLOW
        );
    }
    for operation in [0, 1, 9, 133, 134] {
        assert_eq!(
            evaluate(&program, 202, X86_64, [0, operation, 0, 0, 0, 0]),
            EPERM
        );
    }
}

#[test]
fn dangerous_unselected_syscalls_remain_default_denied() {
    let program = compiled();
    // Hand-authored Linux x86-64 syscall IDs: file/descriptor creation,
    // network, process, namespace, other-process access, privilege and policy.
    for number in [
        2,
        16,
        19,
        20,
        21,
        22,
        32,
        33,
        41,
        53,
        56,
        57,
        58,
        59,
        62,
        72,
        101,
        126,
        135,
        157,
        160,
        165,
        234,
        250,
        257,
        272,
        292,
        293,
        298,
        302,
        308,
        310,
        311,
        317,
        319,
        321,
        322,
        329,
        425,
        426,
        427,
        435,
        437,
        438,
        0xffff_ffff,
    ] {
        assert_eq!(
            evaluate(&program, number, X86_64, [0; 6]),
            EPERM,
            "syscall {number}"
        );
    }
}

#[test]
fn audit_architecture_is_checked_and_x32_numbers_are_not_normalized() {
    let program = compiled();
    for architecture in [0, 0x4000_0003, 0xc000_00b7] {
        assert_eq!(evaluate(&program, 0, architecture, [0; 6]), KILL_PROCESS);
    }
    for number in [0, 1, 3, 9, 10, 60, 228, 318] {
        assert_eq!(
            evaluate(&program, 0x4000_0000 | number, X86_64, [0; 6]),
            EPERM
        );
    }
}
