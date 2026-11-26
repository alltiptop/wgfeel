//! Update from the executable being run, without changing desired or runtime data.
use super::{Result, paths::BinaryUpdate};
use crate::uninstall::{
    installed::Installed,
    services::{HostControl, UpdateControl},
};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    path::{Path, PathBuf},
};

const HELP: &str = "wgfeel update [--dry-run] [--no-start] [--root ABS] [--install-dir PATH]\nUpdates the owned executable, manuals and completion resources.\nRun the newly copied file: ./wgfeel.new update. Configuration, keys and service units are preserved.\nThe previously active service is restarted; the previous binary is retained.\n--no-start requires the service to be stopped and skips service control.\n--root ABS requires --no-start or --dry-run. No downloads are performed.\n";

struct Options {
    root: PathBuf,
    install_dir: PathBuf,
    dry: bool,
    no_start: bool,
}
impl Options {
    fn parse(args: &[OsString], install: bool) -> Result<Self> {
        let mut root = PathBuf::from("/");
        let mut install_dir = None;
        let mut dry = false;
        let mut no_start = false;
        let mut seen = BTreeSet::new();
        let mut arguments = args.iter();
        while let Some(argument) = arguments.next() {
            let name = argument.to_str().ok_or(HELP)?;
            if !seen.insert(name) && !(install && name == "--endpoint") {
                return Err("duplicate installation/update option".into());
            }
            match name {
                "--install-dir" => install_dir = Some(PathBuf::from(arguments.next().ok_or(HELP)?)),
                "--root" => root = PathBuf::from(arguments.next().ok_or(HELP)?),
                "--dry-run" => dry = true,
                "--no-start" => no_start = true,
                "--port" | "--listen-ip" | "--endpoint" | "--id" | "--api-port"
                | "--api-listen-ip" | "--control" | "--traffic"
                    if install =>
                {
                    arguments
                        .next()
                        .and_then(|value| value.to_str())
                        .ok_or(super::HELP)?;
                }
                _ => return Err(if install { super::HELP } else { HELP }.into()),
            }
        }
        let text = root.to_str().ok_or("invalid installation root")?;
        if !root.is_absolute()
            || root.components().collect::<PathBuf>() != root
            || text.split('/').any(|part| part == ".." || part == ".")
            || !text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte))
        {
            return Err("root must be an absolute normalized installation path".into());
        }
        if root != Path::new("/") && !no_start && !dry {
            return Err("--root requires --no-start or --dry-run".into());
        }
        let install_dir = install_dir.unwrap_or_else(|| {
            if root == Path::new("/") {
                crate::default_install_dir()
            } else {
                "/opt/wgfeel".into()
            }
        });
        crate::installation_path(&root, &install_dir)?;
        Ok(Self {
            install_dir,
            root,
            dry,
            no_start,
        })
    }
}

pub(crate) fn existing_install(args: &[OsString]) -> Result<bool> {
    let options = Options::parse(args, true)?;
    let Some(installed) = Installed::inspect(&options.root, &options.install_dir)? else {
        return Ok(false);
    };
    if args.iter().any(|arg| {
        matches!(
            arg.to_str(),
            Some(
                "--control"
                    | "--traffic"
                    | "--port"
                    | "--listen-ip"
                    | "--endpoint"
                    | "--id"
                    | "--api-port"
                    | "--api-listen-ip"
            )
        )
    }) {
        return Err("already installed; use update to preserve configuration, or api port to change the HTTP port".into());
    }
    println!("Existing installation found; updating its executable and preserving configuration.");
    apply_from(
        &options,
        installed,
        &mut HostControl,
        crate::executable::source()?,
    )?;
    Ok(true)
}
pub fn run(args: &[OsString]) -> Result<()> {
    if args == [OsString::from("--help")] {
        print!("{HELP}");
        return Ok(());
    }
    let options = Options::parse(args, false)?;
    let installed = Installed::inspect(&options.root, &options.install_dir)?
        .ok_or("wgfeel is not installed; run install first")?;
    apply_from(
        &options,
        installed,
        &mut HostControl,
        crate::executable::source()?,
    )
}

fn apply_from(
    options: &Options,
    installed: Installed,
    control: &mut impl UpdateControl,
    source: std::fs::File,
) -> Result<()> {
    let directory =
        crate::installation_path(&options.root, &options.install_dir)?.join("instance/bin");
    let mut binary = BinaryUpdate::inspect(&directory, "wgfeel", source)?;
    let resources = installed.resources(&options.root)?;
    let unchanged = binary.unchanged()?;
    if unchanged && resources.unchanged() {
        println!(
            "Installed binary already matches this executable. Configuration and services are unchanged."
        );
        return Ok(());
    }
    if options.dry {
        println!(
            "Update {} and its manual and shell completions from this executable; Preserve configuration, keys and units; retain previous binary. No files or services changed.",
            directory.join("wgfeel").display(),
        );
        return Ok(());
    }
    if unchanged {
        installed.recheck()?;
        resources.apply()?;
        println!("Updated manuals and shell completions. Binary and services are unchanged.");
        return Ok(());
    }
    let mut active = Vec::new();
    if !options.no_start && control.active("wgfeel.service", &installed.unit)? {
        active.push(("wgfeel.service".into(), installed.unit.clone()));
    }
    binary.stage()?;
    let result = replace(&installed, &mut binary, &resources, &active, control);
    // Also attempt service recovery after a partial stop failure.
    let mut failures = Vec::new();
    for (unit, path) in &active {
        if let Err(error) = control.start(unit, path) {
            failures.push(format!("{unit}: {error}"));
        }
    }
    if let Some(name) = binary.backup_name() {
        println!(
            "Previous binary retained at {}",
            directory.join(name).display()
        );
    }
    if let Err(error) = result {
        return Err(if failures.is_empty() {
            error
        } else {
            format!(
                "{error}; service recovery also failed: {}",
                failures.join("; ")
            )
        });
    }
    if !failures.is_empty() {
        return Err(format!(
            "binary updated, but service recovery failed: {}",
            failures.join("; ")
        ));
    }
    println!(
        "Updated {}. Configuration and keys preserved. {}",
        directory.join("wgfeel").display(),
        if options.no_start {
            "Services were not controlled."
        } else {
            "Previously active services restarted."
        }
    );
    Ok(())
}

fn replace(
    installed: &Installed,
    binary: &mut BinaryUpdate,
    resources: &crate::uninstall::resources::Update<'_>,
    active: &[(String, PathBuf)],
    control: &mut impl UpdateControl,
) -> Result<()> {
    for (unit, path) in active {
        control.stop(unit, path)?;
    }
    let _locks = installed.lock_state()?;
    installed.recheck()?;
    resources.apply()?;
    if let Err(error) = binary.commit() {
        // A directory-sync error can occur after the executable was replaced.
        // In that case retain the matching new resources and report the error.
        if binary.backup_name().is_none()
            && let Err(recovery) = resources.rollback()
        {
            return Err(format!("{error}; resource recovery failed: {recovery}"));
        }
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
