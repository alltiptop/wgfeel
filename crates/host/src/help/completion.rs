//! Completion is a separate, read-only entry point. It never dispatches a CLI action.
use super::{CommandHelp, OptionHelp, catalog};
use std::{collections::BTreeMap, ffi::OsString, fmt::Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entity {
    Users,
    Devices,
    Nodes,
}

pub struct Candidate {
    pub value: String,
    pub description: String,
}
impl Candidate {
    pub fn new(value: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            description: description.into(),
        }
    }
}

#[derive(Default)]
pub struct Completion {
    pub candidates: Vec<Candidate>,
    pub entity: Option<Entity>,
    pub prefix: String,
    pub connection: Vec<OsString>,
}

pub(super) fn below(name: &str, path: &str) -> bool {
    path.is_empty()
        || name == path
        || name
            .strip_prefix(path)
            .is_some_and(|rest| rest.starts_with(' '))
}
pub(super) fn options(commands: &[CommandHelp], path: &str) -> Vec<OptionHelp> {
    let mut result = Vec::new();
    if !path.is_empty() {
        for command in commands.iter().filter(|command| below(command.name, path)) {
            result.extend(
                command
                    .options
                    .iter()
                    .copied()
                    .filter(|(option, _)| option.starts_with("--")),
            );
            if command.administrative && command.name != "token rotate" {
                result.extend_from_slice(catalog::CONNECTION);
            }
        }
    } else {
        for command in commands {
            if command.name.is_empty() {
                result.extend_from_slice(&command.options);
            } else if command.name.starts_with("--") && !command.name.contains(' ') {
                result.push((command.name, command.description));
            }
        }
    }
    result.push(("--help", "Show help"));
    result.sort_by_key(|(syntax, _)| *syntax);
    result.dedup_by_key(|(syntax, _)| *syntax);
    result
}
pub(super) fn find_option<'a>(options: &'a [OptionHelp], flag: &str) -> Option<&'a OptionHelp> {
    options
        .iter()
        .find(|(syntax, _)| syntax.split_whitespace().next() == Some(flag))
}

/// Protocol: [INDEX] -- WORDS. WORDS excludes argv[0]; INDEX identifies the
/// current word and defaults to the last word. Shells pass a final empty word
/// after a space. Options after the cursor still select the correct connection.
pub fn request(raw: &[OsString]) -> Completion {
    let (index, words) = match raw {
        [separator, words @ ..] if separator == "--" => (words.len().saturating_sub(1), words),
        [index, separator, words @ ..] if separator == "--" => {
            let Some(index) = index.to_str().and_then(|value| value.parse::<usize>().ok()) else {
                return Completion::default();
            };
            (index, words)
        }
        _ => return Completion::default(),
    };
    if words.is_empty()
        || words.len() > 256
        || index >= words.len()
        || words.iter().map(|word| word.len()).sum::<usize>() > 65536
    {
        return Completion::default();
    }
    let Some(words) = words
        .iter()
        .map(|word| word.to_str())
        .collect::<Option<Vec<_>>>()
    else {
        return Completion::default();
    };
    let commands = catalog::commands();
    let prefix = words[index];
    let mut path = String::new();
    let mut positional = 0;
    let mut pending = None;
    let mut used = BTreeMap::new();
    for word in &words[..index] {
        if let Some((flag, _)) = pending.take() {
            used.insert(flag, *word);
            continue;
        }
        if word.starts_with('-') {
            let available = options(&commands, &path);
            let Some((syntax, _)) = find_option(&available, word) else {
                return Completion::default();
            };
            if let Some((flag, value)) = syntax.split_once(' ') {
                pending = Some((flag, value));
            } else {
                used.insert(word, "");
            }
        } else {
            let next = if path.is_empty() {
                word.to_string()
            } else {
                format!("{path} {word}")
            };
            if positional == 0 && commands.iter().any(|command| below(command.name, &next)) {
                path = next;
            } else if path.is_empty() || !commands.iter().any(|command| command.name == path) {
                return Completion::default();
            } else {
                positional += 1;
            }
        }
    }
    let mut result = Completion {
        prefix: prefix.into(),
        ..Completion::default()
    };
    if let Some((flag, value)) = pending {
        match flag {
            "--control" | "--traffic" => {
                for role in value.split('|') {
                    result.candidates.push(Candidate::new(role, ""));
                }
            }
            "--confirm" => result.candidates.push(Candidate::new("wgfeel", "")),
            "--state-dir" | "--install-dir" | "--root" => {
                result.candidates.push(Candidate::new("@directories", ""))
            }
            "--profile" | "--socket" | "--credential-file" => {
                result.candidates.push(Candidate::new("@files", ""))
            }
            "--user" => result.entity = Some(Entity::Users),
            "--id" if path == "user remove" => result.entity = Some(Entity::Users),
            _ => (),
        }
    } else {
        if positional == 0 && !prefix.starts_with('-') {
            result.entity = match path.as_str() {
                "user show" => Some(Entity::Users),
                "device show" | "device delete" => Some(Entity::Devices),
                "node show" | "node delete" => Some(Entity::Nodes),
                _ => None,
            };
            if path == "completions" {
                for shell in ["bash", "zsh"] {
                    result.candidates.push(Candidate::new(shell, ""));
                }
            }
            for command in &commands {
                let remainder = if path.is_empty() {
                    Some(command.name)
                } else {
                    command.name.strip_prefix(&format!("{path} "))
                };
                if let Some(next) = remainder.and_then(|rest| rest.split_whitespace().next()) {
                    result.candidates.push(Candidate::new(
                        next,
                        command
                            .description
                            .split(". ")
                            .next()
                            .unwrap_or(command.description),
                    ));
                }
            }
        }
        if prefix.is_empty() || prefix.starts_with('-') {
            for (syntax, description) in options(&commands, &path) {
                let flag = syntax.split_whitespace().next().unwrap_or(syntax);
                let repeatable =
                    flag == "--endpoint" && matches!(path.as_str(), "join" | "install");
                if !used.contains_key(flag) || repeatable {
                    result.candidates.push(Candidate::new(flag, description));
                }
            }
        }
    }
    result.candidates.retain(|candidate| {
        candidate.value.starts_with('@') || candidate.value.starts_with(prefix)
    });
    result.candidates.sort_by(|a, b| a.value.cmp(&b.value));
    result.candidates.dedup_by(|a, b| a.value == b.value);
    if result.entity.is_some() {
        let available = options(&commands, &path);
        let mut values = BTreeMap::new();
        let mut i = 0;
        while i < words.len() {
            if let Some((syntax, _)) = find_option(&available, words[i])
                && syntax.contains(' ')
            {
                if ["--socket", "--credential-file", "--profile"].contains(&words[i]) {
                    let Some(value) = words.get(i + 1).filter(|_| i + 1 != index) else {
                        result.entity = None;
                        break;
                    };
                    if values.insert(words[i], *value).is_some() {
                        result.entity = None;
                        break;
                    }
                }
                i += 2;
            } else {
                i += 1;
            }
        }
        for (flag, value) in values {
            result.connection.extend([flag.into(), value.into()]);
        }
    }
    result
}

/// Plain data consumed by native shell completion APIs, never shell source.
pub fn render(candidates: &[Candidate]) -> String {
    let mut out = String::new();
    for candidate in candidates.iter().take(4096) {
        if candidate.value.is_empty()
            || candidate.value.len() > 256
            || candidate.value.chars().any(char::is_control)
        {
            continue;
        }
        let description: String = candidate
            .description
            .chars()
            .take(160)
            .map(|ch| if ch.is_control() { ' ' } else { ch })
            .collect();
        writeln!(out, "{}\t{description}", candidate.value).unwrap();
    }
    out
}

/// Registration scripts use the shell's completion API; all candidate handling
/// is data-only. These adapters also work for binaries invoked by absolute path.
pub fn script(shell: &str) -> Option<String> {
    let source = match shell {
        "bash" => include_str!("completion.bash"),
        "zsh" => include_str!("completion.zsh"),
        _ => return None,
    };
    Some(
        source
            .replace("@BINARY@", "wgfeel")
            .replace("@FUNCTION@", "wgfeel"),
    )
}

pub fn response(
    args: &[OsString],
    dynamic: impl FnOnce(&Completion) -> Vec<Candidate>,
) -> Option<Result<String, &'static str>> {
    match args.first().and_then(|arg| arg.to_str()) {
        Some("_complete") => {
            let mut completion = request(&args[1..]);
            if completion.entity.is_some() {
                let candidates = dynamic(&completion);
                completion.candidates.extend(candidates);
            }
            Some(Ok(render(&completion.candidates)))
        }
        Some("completions")
            if args
                .get(1)
                .is_some_and(|arg| arg == "--help" || arg == "-h") =>
        {
            None
        }
        Some("completions") => Some(match args {
            [_, shell] => shell
                .to_str()
                .and_then(script)
                .ok_or("choose a supported shell: bash or zsh"),
            _ => Err("usage: completions bash|zsh"),
        }),
        _ => None,
    }
}
