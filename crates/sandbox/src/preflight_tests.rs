use super::preflight::{native_personality, private_mappings};

#[test]
fn ordinary_private_runtime_maps_are_accepted() {
    let fixture = "1000-2000 r--p 00000000 103:08 3540264 /usr/bin/worker\n\
                   2000-4000 r-xp 00001000 103:08 3540264 /usr/bin/worker\n\
                   4000-5000 rw-p 00003000 103:08 3540264 /usr/bin/worker\n\
                   8000-a000 rw-p 00000000 00:00 0 [heap]\n\
                   c000-d000 r-xp 00000000 00:00 0 [vdso]\n";
    assert!(private_mappings(fixture));
}

#[test]
fn guard_pages_anonymous_maps_and_paths_with_spaces_are_accepted() {
    let fixture = "1000-2000 ---p 00000000 00:00 0\n\
                   2000-3000 rw-p 00000000 00:00 0\n\
                   3000-4000 r--p 00000000 103:08 123 /tmp/public fixture (deleted)";
    assert!(private_mappings(fixture));
}

#[test]
fn empty_truncated_or_malformed_mapping_records_fail_closed() {
    for fixture in [
        "",
        "\n",
        "1000-2000",
        "1000-2000 r--p 00000000 00:00",
        "1000-2000 r--p 00000000 00:00 0\n\n",
        "1000-2000 r--p 00000000 00:00 0\npartial",
        "not-a-range r--p 00000000 00:00 0",
        "1000-2000-3000 r--p 00000000 00:00 0",
        "1000-10000000000000000 r--p 00000000 00:00 0",
        "1000-2000 r-- 00000000 00:00 0",
        "1000-2000 q--p 00000000 00:00 0",
        "1000-2000 rr-p 00000000 00:00 0",
        "1000-2000 r-rp 00000000 00:00 0",
        "1000-2000 r--q 00000000 00:00 0",
        "1000-2000 r--p invalid 00:00 0",
        "1000-2000 r--p 00000000 invalid 0",
        "1000-2000 r--p 00000000 00:zz 0",
        "1000-2000 r--p 00000000 00:00:00 0",
        "1000-2000 r--p 00000000 00:00 -1",
        "1000-2000 r--p 00000000 00:00 invalid",
        "1000-2000 r--p 00000000 00:00 18446744073709551616",
        "1000-2000 r--p 00000000 00:00 0 /tmp/public\0fixture",
    ] {
        assert!(
            !private_mappings(fixture),
            "accepted malformed map: {fixture:?}"
        );
    }
}

#[test]
fn shared_and_writable_executable_mappings_are_rejected_at_any_position() {
    for permissions in ["r--s", "rw-s", "---s", "r-xs", "rwxs", "rwxp", "-wxp"] {
        let fixture = format!(
            "1000-2000 r--p 00000000 00:00 0\n\
             3000-4000 {permissions} 00000000 103:08 123 /tmp/public fixture\n\
             5000-6000 rw-p 00000000 00:00 0\n"
        );
        assert!(
            !private_mappings(&fixture),
            "accepted permission: {permissions}"
        );
    }
}

#[test]
fn mapping_ranges_must_be_nonempty_ordered_and_nonoverlapping() {
    for fixture in [
        "1000-1000 r--p 00000000 00:00 0",
        "2000-1000 r--p 00000000 00:00 0",
        "3000-4000 r--p 00000000 00:00 0\n1000-2000 rw-p 00000000 00:00 0",
        "1000-3000 r--p 00000000 00:00 0\n2000-4000 rw-p 00000000 00:00 0",
        "1000-2000 r--p 00000000 00:00 0\n1000-2000 rw-p 00000000 00:00 0",
    ] {
        assert!(
            !private_mappings(fixture),
            "accepted invalid range: {fixture:?}"
        );
    }
}

#[test]
fn native_personality_accepts_only_the_zero_proc_value() {
    assert!(native_personality("00000000\n"));
    assert!(native_personality("00000000"));
}

#[test]
fn nonnative_or_malformed_personality_values_fail_closed() {
    for fixture in [
        "",
        "0",
        "0000000",
        "000000000",
        "00400000\n", // READ_IMPLIES_EXEC must not bypass protection-bit checks.
        "00020000\n", // Other inherited personality flags are also unsupported.
        "00000008\n",
        "ffffffff\n",
        "0000000g\n",
        " 00000000\n",
        "00000000 \n",
        "00000000\r\n",
        "00000000\n00000000\n",
        "00000000\n\n",
        "00000000\0",
    ] {
        assert!(
            !native_personality(fixture),
            "accepted personality: {fixture:?}"
        );
    }
}
