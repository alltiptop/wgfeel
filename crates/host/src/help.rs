//! Shared command descriptions for terminal help and the checked-in CLI manual.
//! This module performs no I/O and does not open configuration or credentials.
use std::{ffi::OsString, fmt::Write};
mod catalog;
pub mod completion;
mod man;

/// Relative to /usr/local/share when installed. Files are ordinary readable
/// resources, generated from the same descriptions as the CLI and docs/docs.md.
pub fn resources() -> Vec<(String, String)> {
    let name = "wgfeel";
    vec![
        (format!("man/man1/{name}.1"), man::render()),
        (
            format!("bash-completion/completions/{name}"),
            completion::script("bash").expect("supported shell"),
        ),
        (
            format!("zsh/site-functions/_{name}"),
            completion::script("zsh").expect("supported shell"),
        ),
    ]
}

type OptionHelp = (&'static str, &'static str);
struct CommandHelp {
    name: &'static str,
    arguments: &'static str,
    description: &'static str,
    options: Vec<OptionHelp>,
    examples: &'static [&'static str],
    administrative: bool,
}
impl CommandHelp {
    fn invocation(&self) -> String {
        ["wgfeel", self.name, self.arguments]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

const CONNECTION_DESCRIPTION: &str = "Administrative commands connect to the installed main Unix socket automatically. A downloaded binary defaults to /opt/wgfeel; an installed binary uses its own installation base. Alternatively, pass either --profile or both --socket and --credential-file. Connection options may appear anywhere after user, device, node or config. File ownership and permission checks still apply.";
const GROUPS: &[&str] = &["node", "user", "device", "config", "api", "token"];

fn group_help(group: &str, commands: &[CommandHelp]) -> String {
    let mut out = format!("Usage: wgfeel {group} COMMAND\n\n");
    for command in commands.iter().filter(|c| completion::below(c.name, group)) {
        writeln!(out, "  {}", command.invocation()).unwrap();
    }
    writeln!(
        out,
        "\nUse wgfeel {group} COMMAND --help for options and examples."
    )
    .unwrap();
    out
}

/// Render help without opening state or connecting to a service.
pub fn requested(args: &[OsString]) -> Option<String> {
    let path = if args.is_empty()
        || matches!(args, [group] if group != "user" && group.to_str().is_some_and(|name| GROUPS.contains(&name)))
    {
        args
    } else if args.first().is_some_and(|arg| arg == "help") {
        &args[1..]
    } else if args
        .last()
        .is_some_and(|arg| arg == "--help" || arg == "-h")
    {
        &args[..args.len() - 1]
    } else {
        return None;
    };
    if path.is_empty() {
        let commands = catalog::commands();
        let mut out = String::from("Usage: wgfeel COMMAND [OPTIONS]\n\n");
        for command in &commands {
            if command.name.contains(' ') || GROUPS.contains(&command.name) {
                continue;
            }
            writeln!(
                out,
                "  {:<14} {}",
                command.name,
                command
                    .description
                    .split(". ")
                    .next()
                    .unwrap_or(command.description)
                    .trim_end_matches('.')
            )
            .unwrap();
        }
        out.push('\n');
        for group in GROUPS {
            let actions = commands
                .iter()
                .filter_map(|command| {
                    let (parent, action) = command.name.split_once(' ')?;
                    (parent == *group).then_some(action)
                })
                .collect::<Vec<_>>();
            let hint = if *group == "user" {
                " (or open the interactive menu)"
            } else {
                ""
            };
            writeln!(out, "  {group:<14} {}{hint}", actions.join(", ")).unwrap();
        }
        writeln!(out, "\nUse wgfeel COMMAND --help for options and examples.").unwrap();
        return Some(out);
    }
    // Resolve only the command path. Values and positionals must never trigger
    // normal dispatch (opening state, connecting, or mutating) for a help request.
    let commands = catalog::commands();
    let mut words = path.iter();
    let mut path = String::new();
    let mut positional = false;
    while let Some(word) = words.next() {
        let word = word.to_str()?;
        let next = if path.is_empty() {
            word.to_owned()
        } else {
            format!("{path} {word}")
        };
        if !positional && commands.iter().any(|c| completion::below(c.name, &next)) {
            path = next;
        } else if word.starts_with('-') {
            let options = completion::options(&commands, &path);
            let (syntax, _) = completion::find_option(&options, word)?;
            if syntax.contains(' ') {
                words.next()?;
            }
        } else if GROUPS.contains(&path.as_str()) || !commands.iter().any(|c| c.name == path) {
            return None;
        } else {
            positional = true;
        }
    }
    if GROUPS.contains(&path.as_str()) {
        return Some(group_help(&path, &commands));
    }
    let command = commands.into_iter().find(|c| c.name == path)?;
    let mut out = format!(
        "Usage: {}\n\n{}\n",
        command.invocation(),
        command.description
    );
    let mut options = command.options;
    if command.administrative && command.name != "token rotate" {
        options.extend_from_slice(catalog::CONNECTION);
    }
    if !options.is_empty() {
        out.push_str("\nArguments and options:\n");
        for (option, description) in options {
            writeln!(out, "  {option}\n    {description}").unwrap();
        }
    }
    if !command.examples.is_empty() {
        out.push_str("\nExamples:\n");
        for example in command.examples {
            writeln!(out, "  {example}").unwrap();
        }
    }
    Some(out)
}

fn anchor(name: &str) -> String {
    format!(
        "{}-{}",
        "wgfeel",
        if name.is_empty() {
            "run"
        } else {
            name.trim_start_matches('-')
        }
    )
    .replace(' ', "-")
}
fn cell(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('|', "&#124;")
        .replace('\n', "<br>")
}
fn code_cell(text: &str) -> String {
    // GFM table delimiters must be escaped even inside a code span. HTML
    // entities inside code spans would be displayed literally.
    format!("`{}`", text.replace('|', "\\|"))
}

/// Deterministic Markdown generated from the same descriptions as --help.
pub fn markdown() -> String {
    let mut out = String::from(
        "<!-- Generated by cargo docs from crates/host/src/help; do not edit by hand. -->\n\n# Command reference\n\n[README](../README.md) · [Getting started](GETTING_STARTED.md) · [Contributing](CONTRIBUTING.md)\n\n`wgfeel` runs one instance with independent `main`/`child` control and `entry`/`relay`/`off` traffic capabilities.\nInstallations use one executable and one service.\n\n`[VALUE]` is optional; uppercase values are placeholders. Quote names containing\nspaces. Public endpoints below use documentation-only addresses: replace them\nwith your own. Interactive selection uses numbers; explicit arguments use IDs.\n\n## Contents\n\n- [Connection options](#connection-options)\n- [wgfeel](#wgfeel)\n\n## Connection options\n\n",
    );
    writeln!(out, "{CONNECTION_DESCRIPTION}\n").unwrap();
    out.push_str("| Option | Description |\n| --- | --- |\n");
    for (option, description) in catalog::CONNECTION {
        writeln!(out, "| {} | {} |", code_cell(option), cell(description)).unwrap();
    }
    {
        writeln!(out, "\n## wgfeel\n").unwrap();
        let commands = catalog::commands();
        out.push_str("| Command | Purpose |\n| --- | --- |\n");
        for command in &commands {
            let label = if command.name.is_empty() {
                "run in foreground"
            } else {
                command.name
            };
            let summary = command
                .description
                .split(". ")
                .next()
                .unwrap_or(command.description)
                .trim_end_matches('.');
            writeln!(
                out,
                "| [{}](#{}) | {} |",
                cell(label),
                anchor(command.name),
                cell(summary)
            )
            .unwrap();
        }
        for command in commands {
            let label = if command.name.is_empty() {
                "run"
            } else {
                command.name
            };
            writeln!(
                out,
                "\n<a id=\"{}\"></a>\n\n### wgfeel {}\n\n```text\n{}\n```\n\n{}\n",
                anchor(command.name),
                label,
                command.invocation(),
                command.description
            )
            .unwrap();
            if command.administrative && command.name != "token rotate" {
                out.push_str("Accepts the [connection options](#connection-options).\n\n");
            }
            if !command.options.is_empty() {
                out.push_str("| Argument / option | Description |\n| --- | --- |\n");
                for (option, description) in command.options {
                    writeln!(out, "| {} | {} |", code_cell(option), cell(description)).unwrap();
                }
                out.push('\n');
            }
            if !command.examples.is_empty() {
                out.push_str("Example:\n\n```sh\n");
                for example in command.examples {
                    writeln!(out, "{example}").unwrap();
                }
                out.push_str("```\n");
            }
        }
    }
    out
}
