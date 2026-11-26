//! Repository documentation generator; no installed services or credentials are used.
use std::{ffi::OsString, fs, io::Write, path::Path, process::ExitCode};

fn generate(destination: &Path, check: bool) -> Result<bool, String> {
    let expected = wgfeel_host::help::markdown();
    write_artifact(destination, &expected, check)
}

fn write_artifact(destination: &Path, expected: &str, check: bool) -> Result<bool, String> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) if !metadata.is_file() => {
            return Err("documentation destination must be a regular file, not a symlink".into());
        }
        Ok(_) => {
            let current = fs::read(destination).map_err(|_| "cannot read docs.md")?;
            if current == expected.as_bytes() {
                return Ok(false);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err("cannot inspect docs.md".into()),
    }
    if check {
        return Err(format!(
            "{} is missing or outdated; run cargo docs",
            destination.display()
        ));
    }
    // Replace the generated file only after the complete output has been written.
    let temporary = destination.with_extension(format!("{}.tmp", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|_| "cannot create temporary documentation file")?;
    let result = file
        .write_all(expected.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temporary, destination));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|_| "cannot replace docs.md")?;
    Ok(true)
}

fn run(args: &[OsString]) -> Result<(), String> {
    if args == [OsString::from("--help")] || args == [OsString::from("-h")] {
        println!(
            "Usage: cargo docs [--check]\n\nGenerate docs/docs.md, section-1 manual pages and Bash/Zsh adapters under share/.\n--check reports missing or outdated artifacts without writing files.\nNo services, credentials or network access are required."
        );
        return Ok(());
    }
    let check = match args {
        [] => false,
        [arg] if arg == "--check" => true,
        _ => return Err("usage: cargo docs [--check]".into()),
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let destination = root.join("docs/docs.md");
    let changed = generate(&destination, check)?;
    println!(
        "docs/docs.md: {}",
        if changed { "generated" } else { "up to date" }
    );
    {
        for (relative, contents) in wgfeel_host::help::resources() {
            let destination = root.join("share").join(relative);
            if !check {
                let parent = destination.parent().ok_or("invalid generated path")?;
                let mut current = root.clone();
                for part in parent
                    .strip_prefix(&root)
                    .map_err(|_| "invalid generated path")?
                    .components()
                {
                    current.push(part);
                    match fs::symlink_metadata(&current) {
                        Ok(metadata) if metadata.is_dir() => (),
                        Ok(_) => {
                            return Err(
                                "generated directory is not a directory or is a symlink".into()
                            );
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            fs::create_dir(&current)
                                .map_err(|_| "cannot create generated directory")?
                        }
                        Err(_) => return Err("cannot inspect generated directory".into()),
                    }
                }
            }
            let changed = write_artifact(&destination, &contents, check)?;
            println!(
                "{}: {}",
                destination
                    .strip_prefix(&root)
                    .unwrap_or(&destination)
                    .display(),
                if changed { "generated" } else { "up to date" }
            );
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(&std::env::args_os().skip(1).collect::<Vec<_>>()) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("docs: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "wgfeel-docs-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn file(&self) -> std::path::PathBuf {
            self.0.join("docs.md")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn generation_is_deterministic_and_covers_common_commands() {
        let fixture = Fixture::new();
        assert!(generate(&fixture.file(), false).unwrap());
        let first = fs::read_to_string(fixture.file()).unwrap();
        for command in [
            "wgfeel user add",
            "wgfeel device show",
            "wgfeel node add",
            "wgfeel join",
        ] {
            assert!(first.contains(command), "missing command: {command}");
        }
        assert!(first.contains("--profile"));
        assert!(!generate(&fixture.file(), false).unwrap());
        assert!(!generate(&fixture.file(), true).unwrap());
        assert_eq!(first, fs::read_to_string(fixture.file()).unwrap());
    }

    #[test]
    fn check_detects_missing_and_stale_files_without_writing() {
        let fixture = Fixture::new();
        assert!(generate(&fixture.file(), true).is_err());
        assert!(!fixture.file().exists());
        fs::write(fixture.file(), "old documentation\n").unwrap();
        assert!(generate(&fixture.file(), true).is_err());
        assert_eq!(
            fs::read_to_string(fixture.file()).unwrap(),
            "old documentation\n"
        );
    }

    #[test]
    fn generation_does_not_follow_a_symlink() {
        let fixture = Fixture::new();
        let other = fixture.0.join("other.md");
        fs::write(&other, "keep me").unwrap();
        std::os::unix::fs::symlink(&other, fixture.file()).unwrap();
        assert!(generate(&fixture.file(), false).is_err());
        assert_eq!(fs::read_to_string(other).unwrap(), "keep me");
    }

    #[test]
    fn unknown_arguments_are_rejected() {
        assert!(run(&["--unknown".into()]).is_err());
        assert!(run(&["--check".into(), "--check".into()]).is_err());
    }
}
