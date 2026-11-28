use super::*;
use std::{
    fs,
    sync::atomic::{AtomicUsize, Ordering},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "wgfeel-source-check-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn write(&self, path: &str, bytes: impl AsRef<[u8]>) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fn rejected(&self, checkout: bool) -> Vec<PathBuf> {
        inspect(&self.0, checkout)
            .unwrap()
            .problems
            .into_iter()
            .map(|(path, _)| path)
            .collect()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn accepts_sources_unicode_licenses_and_native_shell_resources() {
    let fixture = Fixture::new();
    for path in [
        "src/main.rs",
        "README.md",
        "Cargo.toml",
        "Cargo.lock",
        "LICENSE",
        ".gitignore",
        ".github/workflows/checks.yml",
        ".agents/skills/test/SKILL.md",
        "share/bash-completion/completions/wgfeel",
        "share/zsh/site-functions/_wgfeel",
        "share/man/man1/wgfeel.1",
    ] {
        fixture.write(path, "text with Unicode: network ⇄ mesh\n");
    }
    let report = inspect(&fixture.0, true).unwrap();
    assert!(report.problems.is_empty());
    assert_eq!(report.checked, 11);
}

#[test]
fn rejects_binary_contents_even_with_source_names_and_after_a_text_prefix() {
    let fixture = Fixture::new();
    fixture.write("ELF.rs", b"\x7fELF\x02\x01");
    fixture.write("invalid.md", [0xff, 0xfe, 0x41]);
    let mut bytes = vec![b' '; 32768];
    for chunk in bytes.chunks_mut(1024) {
        chunk[0] = b'\n';
    }
    bytes.push(0);
    fixture.write("tail.txt", &bytes);
    assert_eq!(
        fixture.rejected(false),
        ["ELF.rs", "invalid.md", "tail.txt"].map(PathBuf::from)
    );
    assert_eq!(fs::read(fixture.0.join("tail.txt")).unwrap(), bytes);
}

#[test]
fn rejects_empty_or_textual_artifacts_and_disguised_lfs_pointers() {
    let fixture = Fixture::new();
    fixture.write("empty.bin", b"");
    fixture.write("fixture.blob", b"placeholder");
    fixture.write("image.png", b"not an image");
    fixture.write("wgfeel", b"");
    fixture.write(
        "pointer.md",
        "version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 123\n",
    );
    assert_eq!(
        fixture.rejected(false),
        [
            "empty.bin",
            "fixture.blob",
            "image.png",
            "pointer.md",
            "wgfeel"
        ]
        .map(PathBuf::from)
    );
}

#[test]
fn enforces_exact_size_and_line_limits() {
    let fixture = Fixture::new();
    let mut bytes = vec![b'x'; MAX_FILE_BYTES];
    for chunk in bytes.chunks_mut(1024) {
        chunk[0] = b'\n';
    }
    fixture.write("size.txt", &bytes);
    fixture.write("line.txt", vec![b'x'; MAX_LINE_BYTES]);
    assert!(fixture.rejected(false).is_empty());
    bytes.push(b'\n');
    fixture.write("size.txt", bytes);
    fixture.write("line.txt", vec![b'x'; MAX_LINE_BYTES + 1]);
    assert_eq!(
        fixture.rejected(false),
        ["line.txt", "size.txt"].map(PathBuf::from)
    );
}

#[test]
fn ignores_only_known_local_roots_and_rejects_them_in_fresh_checkouts() {
    let fixture = Fixture::new();
    for path in [
        "target/debug/app",
        "tmp/payload.bin",
        ".codex/session.json",
        ".aws/credentials",
        ".kateproject",
    ] {
        fixture.write(path, b"local-only");
    }
    fixture.write(".git/objects/object", [0xff]);
    assert!(fixture.rejected(false).is_empty());
    assert_eq!(
        fixture.rejected(true),
        [".aws", ".codex", ".kateproject", "target", "tmp"].map(PathBuf::from)
    );
}

#[test]
fn gitignore_and_nested_output_names_cannot_hide_source_blobs() {
    let fixture = Fixture::new();
    fixture.write(".gitignore", "hidden/\n*.bin\n");
    fixture.write("hidden/payload.bin", [0, 1, 2]);
    fixture.write("src/target/hidden.md", [0, 1, 2]);
    fixture.write("src/tmp/hidden.md", [0, 1, 2]);
    assert_eq!(
        fixture.rejected(false),
        [
            "hidden/payload.bin",
            "src/target/hidden.md",
            "src/tmp/hidden.md"
        ]
        .map(PathBuf::from)
    );
}

#[test]
fn rejects_symlinks_without_following_them() {
    let fixture = Fixture::new();
    let outside = Fixture::new();
    outside.write("secret.txt", b"must not read or print");
    std::os::unix::fs::symlink(&outside.0, fixture.0.join("linked")).unwrap();
    std::os::unix::fs::symlink(outside.0.join("secret.txt"), fixture.0.join("linked.md")).unwrap();
    assert_eq!(
        fixture.rejected(true),
        ["linked", "linked.md"].map(PathBuf::from)
    );
    assert_eq!(
        fs::read(outside.0.join("secret.txt")).unwrap(),
        b"must not read or print"
    );
}

#[test]
fn missing_root_and_unknown_arguments_fail() {
    let fixture = Fixture::new();
    assert!(inspect(&fixture.0.join("missing"), false).is_err());
    assert!(run(&["--unknown".into()]).is_err());
}
