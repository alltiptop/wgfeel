//! Source-only repository check. Uses std only; never invokes Git or writes files.
use std::{ffi::OsString, fs, io::Read, path::Path, path::PathBuf, process::ExitCode};

const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_LINE_BYTES: usize = 16 * 1024;

// These are local workspace roots, not a replacement for .gitignore. CI rejects
// them in a fresh checkout, before Cargo can create target/ or any test data.
const LOCAL_ONLY: &[&str] = &[
    "target",
    "debug",
    "tmp",
    "temp",
    "state",
    "backups",
    "private",
    "exports",
    ".codex",
    ".aws",
    ".claude",
    ".claude.json",
    "CLAUDE.local.md",
    ".cursor",
    ".opencode",
    ".gemini",
    ".continue",
    ".goose",
    ".windsurf",
    ".cline",
    ".roo",
    ".kilocode",
    ".vscode",
    ".idea",
    ".zed",
    ".fleet",
    ".kateproject",
    ".kateproject.d",
    ".kateproject.local",
    ".cache",
    "logs",
    "coverage",
    "lcov.info",
    ".DS_Store",
    ".directory",
    "Thumbs.db",
    "Desktop.ini",
];

fn local_only(name: &str) -> bool {
    LOCAL_ONLY.contains(&name)
        || name.starts_with(".aider")
        || name.ends_with(".code-workspace")
        || (name == ".env" || name.starts_with(".env.")) && name != ".env.example"
}

fn source_path(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(
            "LICENSE"
                | "COPYING"
                | "NOTICE"
                | "README"
                | "Dockerfile"
                | "Containerfile"
                | ".gitignore"
                | ".gitattributes"
                | ".dockerignore"
                | ".editorconfig"
                | ".env.example"
        )
    ) || matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some(
            "rs" | "toml" | "lock" | "md" | "txt" | "json" | "yml" | "yaml" | "bash" | "zsh" | "1"
        )
    ) || matches!(
        path.to_str(),
        Some("share/bash-completion/completions/wgfeel" | "share/zsh/site-functions/_wgfeel")
    )
}

fn text_problem(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() > MAX_FILE_BYTES {
        return Some("file exceeds the 1-MiB source limit; generate data at runtime");
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Some("binary/non-UTF-8 contents are forbidden");
    };
    if text
        .chars()
        .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
    {
        return Some("binary control characters are forbidden");
    }
    for line in text.split('\n') {
        if line.len() > MAX_LINE_BYTES {
            return Some("line exceeds 16 KiB; embedded payload blobs are forbidden");
        }
        if line
            .trim_start()
            .starts_with("version https://git-lfs.github.com/spec/v1")
        {
            return Some("Git LFS payload pointers are forbidden");
        }
    }
    None
}

#[derive(Default)]
struct Report {
    checked: usize,
    problems: Vec<(PathBuf, &'static str)>,
}

fn inspect(root: &Path, checkout: bool) -> Result<Report, String> {
    let metadata =
        fs::symlink_metadata(root).map_err(|error| format!("cannot inspect root: {error}"))?;
    if !metadata.is_dir() {
        return Err("root must be a directory, not a file or symlink".into());
    }
    let mut report = Report::default();
    walk(root, Path::new(""), checkout, &mut report)?;
    Ok(report)
}

fn walk(root: &Path, directory: &Path, checkout: bool, report: &mut Report) -> Result<(), String> {
    let mut entries = fs::read_dir(root.join(directory))
        .and_then(|entries| {
            entries
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<Result<Vec<_>, _>>()
        })
        .map_err(|error| format!("cannot enumerate {directory:?}: {error}"))?;
    entries.sort();
    for name in entries {
        let relative = directory.join(&name);
        if directory.as_os_str().is_empty() {
            if name == ".git" {
                continue;
            }
            if name.to_str().is_some_and(local_only) {
                if checkout {
                    report.problems.push((
                        relative,
                        "local-only path must not be published in a source checkout",
                    ));
                }
                continue;
            }
        }
        let path = root.join(&relative);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect {relative:?}: {error}"))?;
        if metadata.is_dir() {
            walk(root, &relative, checkout, report)?;
            continue;
        }
        let problem = if !metadata.is_file() {
            Some("only regular source files are allowed; symlinks and special files are forbidden")
        } else if !source_path(&relative) {
            Some(
                "unsupported source file type; binaries, archives and payload fixtures are forbidden",
            )
        } else if metadata.len() > MAX_FILE_BYTES as u64 {
            Some("file exceeds the 1-MiB source limit; generate data at runtime")
        } else {
            let mut bytes = Vec::new();
            fs::File::open(&path)
                .and_then(|file| {
                    file.take((MAX_FILE_BYTES + 1) as u64)
                        .read_to_end(&mut bytes)
                })
                .map_err(|error| format!("cannot read {relative:?}: {error}"))?;
            report.checked += 1;
            text_problem(&bytes)
        };
        if let Some(reason) = problem {
            report.problems.push((relative, reason));
        }
    }
    Ok(())
}

fn run(args: &[OsString]) -> Result<bool, String> {
    if args == [OsString::from("--help")] {
        println!(
            "Usage: cargo check-blobs [--checkout] [ROOT]\n\nCheck source file types, text contents and size limits without Git.\n--checkout rejects local-only paths instead of skipping them; use on a fresh checkout."
        );
        return Ok(true);
    }
    let default = option_env!("CARGO_MANIFEST_DIR")
        .map(|path| Path::new(path).join("../.."))
        .unwrap_or_else(|| PathBuf::from("."));
    let (checkout, root) = match args {
        [] => (false, default),
        [flag] if flag == "--checkout" => (true, default),
        [flag, root] if flag == "--checkout" => (true, PathBuf::from(root)),
        [root] if !root.to_string_lossy().starts_with('-') => (false, PathBuf::from(root)),
        _ => return Err("usage: cargo check-blobs [--checkout] [ROOT]".into()),
    };
    let report = inspect(&root, checkout)?;
    for (path, reason) in &report.problems {
        // Debug formatting escapes control characters in untrusted file names.
        eprintln!("{path:?}: {reason}");
    }
    if report.problems.is_empty() {
        println!("Source check passed: {} text files.", report.checked);
        Ok(true)
    } else {
        eprintln!(
            "Source check failed: {} violation(s).",
            report.problems.len()
        );
        Ok(false)
    }
}

fn main() -> ExitCode {
    match run(&std::env::args_os().skip(1).collect::<Vec<_>>()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("check-blobs: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
