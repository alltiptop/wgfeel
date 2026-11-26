use super::{Options, Response, USAGE, valid_id};
use serde::Deserialize;
use std::io::{BufRead, Write};

type Api<'a> = dyn Fn(&str, &str, Option<u64>, &[u8]) -> Result<Response> + 'a;
type Result<T> = std::result::Result<T, &'static str>;
const IO_ERROR: &str = "cannot read or write terminal";

#[derive(Clone, Deserialize)]
struct User {
    id: String,
    name: String,
    suspended: bool,
    devices: Vec<Device>,
}
#[derive(Clone, Deserialize)]
struct Device {
    id: String,
    metadata: Metadata,
}
#[derive(Clone, Deserialize)]
struct Metadata {
    name: Option<String>,
}
impl Device {
    fn name(&self) -> &str {
        self.metadata.name.as_deref().unwrap_or("Unnamed device")
    }
}
fn clean(text: &str) -> String {
    crate::output::escape(text)
}

fn line(input: &mut dyn BufRead, out: &mut dyn Write, prompt: &str) -> Result<Option<String>> {
    write!(out, "{prompt}")
        .and_then(|_| out.flush())
        .map_err(|_| IO_ERROR)?;
    let mut value = String::new();
    if input.read_line(&mut value).map_err(|_| IO_ERROR)? == 0 {
        return Ok(None);
    }
    if value.len() > 1024 {
        return Err("input is too long");
    }
    Ok(Some(value.trim().to_owned()))
}
fn name(input: &mut dyn BufRead, out: &mut dyn Write, prompt: &str) -> Result<Option<String>> {
    loop {
        let Some(value) = line(input, out, prompt)? else {
            return Ok(None);
        };
        if !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control) {
            return Ok(Some(value));
        }
        writeln!(
            out,
            "Enter a name of 1–128 bytes without control characters."
        )
        .map_err(|_| IO_ERROR)?;
    }
}
pub(super) fn confirm(
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    question: &str,
) -> Result<bool> {
    let yes = line(input, out, &format!("{question} (y/n) [n]: "))?.as_deref() == Some("y");
    if !yes {
        writeln!(out, "Cancelled.").map_err(|_| IO_ERROR)?;
    }
    Ok(yes)
}
fn choice(input: &mut dyn BufRead, out: &mut dyn Write, count: usize) -> Result<Option<usize>> {
    writeln!(out, "0. back / exit").map_err(|_| IO_ERROR)?;
    loop {
        let Some(value) = line(input, out, "> ")? else {
            return Ok(None);
        };
        if value.is_empty() || value == "0" {
            return Ok(None);
        }
        if let Ok(n) = value.trim_end_matches('.').parse::<usize>()
            && n > 0
            && n <= count
        {
            return Ok(Some(n - 1));
        }
        writeln!(out, "Choose 1–{count}, or 0 to go back.").map_err(|_| IO_ERROR)?;
    }
}
fn optional_id(options: &mut Options) -> Result<Option<String>> {
    if options.positional.is_empty() {
        Ok(None)
    } else {
        options.id().map(Some)
    }
}

struct Ui<'a> {
    api: &'a Api<'a>,
    input: &'a mut dyn BufRead,
    out: &'a mut dyn Write,
}
impl Ui<'_> {
    fn request(
        &mut self,
        method: &str,
        path: &str,
        revision: Option<u64>,
        body: &[u8],
    ) -> Result<Response> {
        let response = (self.api)(method, path, revision, body)?;
        if !(200..300).contains(&response.status) {
            #[derive(Deserialize)]
            struct Error {
                error: String,
            }
            let error: Error = serde_json::from_slice(&response.body)
                .map_err(|_| "invalid Management response")?;
            writeln!(self.out, "Management: {}", clean(&error.error)).map_err(|_| IO_ERROR)?;
            return Err("Management rejected request");
        }
        Ok(response)
    }
    fn users(&mut self) -> Result<(Vec<User>, u64)> {
        let response = self.request("GET", "/api/v1/users", None, b"")?;
        #[derive(Deserialize)]
        struct Users {
            users: Vec<User>,
        }
        let users: Users =
            serde_json::from_slice(&response.body).map_err(|_| "invalid user list")?;
        Ok((
            users.users,
            response.generation.ok_or("Management omitted revision")?,
        ))
    }
    fn select_user(&mut self, id: Option<&str>) -> Result<Option<(User, u64)>> {
        let (users, revision) = self.users()?;
        if let Some(id) = id {
            return users
                .into_iter()
                .find(|user| user.id == id)
                .map(|user| Some((user, revision)))
                .ok_or("user not found");
        }
        if users.is_empty() {
            writeln!(self.out, "No users.").map_err(|_| IO_ERROR)?;
            return Ok(None);
        }
        for (i, user) in users.iter().enumerate() {
            writeln!(
                self.out,
                "{}. {}, {} devices ({}){}",
                i + 1,
                clean(&user.name),
                user.devices.len(),
                user.id,
                if user.suspended { " — suspended" } else { "" }
            )
            .map_err(|_| IO_ERROR)?;
        }
        Ok(choice(self.input, self.out, users.len())?.map(|i| (users[i].clone(), revision)))
    }
    fn select_device(&mut self, user: &User) -> Result<Option<Device>> {
        writeln!(self.out, "{}: {}\ndevices", clean(&user.name), user.id).map_err(|_| IO_ERROR)?;
        if user.devices.is_empty() {
            writeln!(self.out, "No devices.").map_err(|_| IO_ERROR)?;
            return Ok(None);
        }
        for (i, device) in user.devices.iter().enumerate() {
            writeln!(
                self.out,
                "{}. {} ({})",
                i + 1,
                clean(device.name()),
                device.id
            )
            .map_err(|_| IO_ERROR)?;
        }
        Ok(choice(self.input, self.out, user.devices.len())?.map(|i| user.devices[i].clone()))
    }
    fn find_device(&mut self, id: Option<&str>) -> Result<Option<(User, Device, u64)>> {
        if let Some(id) = id {
            let (users, revision) = self.users()?;
            for user in users {
                if let Some(device) = user.devices.iter().find(|device| device.id == id).cloned() {
                    return Ok(Some((user, device, revision)));
                }
            }
            return Err("device not found");
        }
        let Some((user, revision)) = self.select_user(None)? else {
            return Ok(None);
        };
        Ok(self
            .select_device(&user)?
            .map(|device| (user, device, revision)))
    }
    fn create_device(&mut self, user: &User, device_name: &str, revision: u64) -> Result<String> {
        let body = serde_json::to_vec(&serde_json::json!({"name":device_name}))
            .map_err(|_| "cannot encode request")?;
        let response = self.request(
            "POST",
            &format!("/api/v1/users/{}/devices", user.id),
            Some(revision),
            &body,
        )?;
        #[derive(Deserialize)]
        struct Created {
            id: String,
        }
        let created: Created =
            serde_json::from_slice(&response.body).map_err(|_| "invalid creation response")?;
        writeln!(
            self.out,
            "Device added: {} ({})",
            clean(device_name),
            created.id
        )
        .map_err(|_| IO_ERROR)?;
        Ok(created.id)
    }
    fn add_user(&mut self, supplied: Option<String>) -> Result<()> {
        let username = match supplied {
            Some(value) => value,
            None => match name(self.input, self.out, "Username: ")? {
                Some(value) => value,
                None => return Ok(()),
            },
        };
        let Some(device_name) = name(self.input, self.out, "New device name: ")? else {
            return Ok(());
        };
        let (_, revision) = self.users()?;
        let body = serde_json::to_vec(&serde_json::json!({"name":username}))
            .map_err(|_| "cannot encode request")?;
        let response = self.request("POST", "/api/v1/users", Some(revision), &body)?;
        #[derive(Deserialize)]
        struct Created {
            id: String,
        }
        let created: Created =
            serde_json::from_slice(&response.body).map_err(|_| "invalid creation response")?;
        writeln!(
            self.out,
            "User added: {} ({})",
            clean(&username),
            created.id
        )
        .map_err(|_| IO_ERROR)?;
        let (user, revision) = self
            .select_user(Some(&created.id))?
            .ok_or("user not found")?;
        self.create_device(&user, &device_name, revision)?;
        self.user_menu(&created.id)
    }
    fn remove_user(&mut self, user: User, revision: u64) -> Result<bool> {
        if !confirm(
            self.input,
            self.out,
            &format!(
                "Delete user {} ({}) and all {} devices?",
                clean(&user.name),
                user.id,
                user.devices.len()
            ),
        )? {
            return Ok(false);
        }
        self.request(
            "DELETE",
            &format!("/api/v1/users/{}", user.id),
            Some(revision),
            b"",
        )?;
        writeln!(
            self.out,
            "User deleted: {} ({})",
            clean(&user.name),
            user.id
        )
        .map_err(|_| IO_ERROR)?;
        Ok(true)
    }
    fn remove_device(&mut self, user: &User, device: &Device, revision: u64) -> Result<bool> {
        if !confirm(
            self.input,
            self.out,
            &format!(
                "Delete device {} ({}) from user {} ({})?",
                clean(device.name()),
                device.id,
                clean(&user.name),
                user.id
            ),
        )? {
            return Ok(false);
        }
        self.request(
            "DELETE",
            &format!("/api/v1/users/{}/devices/{}", user.id, device.id),
            Some(revision),
            b"",
        )?;
        writeln!(
            self.out,
            "Device deleted: {} ({})",
            clean(device.name()),
            device.id
        )
        .map_err(|_| IO_ERROR)?;
        Ok(true)
    }
    fn device_menu(&mut self, id: &str) -> Result<()> {
        loop {
            let Some((user, device, revision)) = self.find_device(Some(id))? else {
                return Ok(());
            };
            writeln!(
                self.out,
                "\n{}: {}\n{}: {}\n1. delete\n\nconfig:",
                clean(&user.name),
                user.id,
                clean(device.name()),
                device.id
            )
            .map_err(|_| IO_ERROR)?;
            // The response owns and zeroizes the exported private key; do not deserialize/copy it.
            let response = (self.api)(
                "GET",
                &format!("/api/v1/users/{}/devices/{}/config", user.id, device.id),
                None,
                b"",
            )?;
            if response.status == 200 && response.is_config {
                self.out.write_all(&response.body).map_err(|_| IO_ERROR)?;
            } else {
                writeln!(
                    self.out,
                    "Configuration unavailable (HTTP {}).",
                    response.status
                )
                .map_err(|_| IO_ERROR)?;
            }
            match choice(self.input, self.out, 1)? {
                Some(0) => {
                    if self.remove_device(&user, &device, revision)? {
                        return Ok(());
                    }
                }
                _ => return Ok(()),
            }
        }
    }
    fn user_menu(&mut self, id: &str) -> Result<()> {
        loop {
            let Some((user, revision)) = self.select_user(Some(id))? else {
                return Ok(());
            };
            writeln!(
                self.out,
                "\n{}: {}\nStatus: {}\n1. add device\n2. remove user\n3. {} user\n4. show devices",
                clean(&user.name),
                user.id,
                if user.suspended {
                    "suspended"
                } else {
                    "active"
                },
                if user.suspended { "resume" } else { "suspend" }
            )
            .map_err(|_| IO_ERROR)?;
            match choice(self.input, self.out, 4)? {
                Some(0) => {
                    if let Some(device_name) = name(self.input, self.out, "Device name: ")? {
                        let id = self.create_device(&user, &device_name, revision)?;
                        self.device_menu(&id)?;
                    } else {
                        return Ok(());
                    }
                }
                Some(1) => {
                    if self.remove_user(user, revision)? {
                        return Ok(());
                    }
                }
                Some(2) => {
                    self.request(
                        "POST",
                        &format!(
                            "/api/v1/users/{}/{}",
                            user.id,
                            if user.suspended { "resume" } else { "suspend" }
                        ),
                        Some(revision),
                        b"{}",
                    )?;
                    writeln!(
                        self.out,
                        "Access {}. Nodes apply this with the new configuration.",
                        if user.suspended {
                            "resumed"
                        } else {
                            "suspended"
                        }
                    )
                    .map_err(|_| IO_ERROR)?;
                }
                Some(3) => {
                    if let Some(device) = self.select_device(&user)? {
                        self.device_menu(&device.id)?;
                    }
                }
                _ => return Ok(()),
            }
        }
    }
    fn user_list(&mut self) -> Result<()> {
        while let Some((user, _)) = self.select_user(None)? {
            self.user_menu(&user.id)?;
        }
        Ok(())
    }
    fn home(&mut self) -> Result<()> {
        loop {
            writeln!(self.out, "1. add user\n2. remove user\n3. show list")
                .map_err(|_| IO_ERROR)?;
            match choice(self.input, self.out, 3)? {
                Some(0) => self.add_user(None)?,
                Some(1) => {
                    if let Some((user, revision)) = self.select_user(None)? {
                        self.remove_user(user, revision)?;
                    }
                }
                Some(2) => self.user_list()?,
                _ => return Ok(()),
            }
        }
    }
}
pub(super) fn run(
    kind: &str,
    mut options: Options,
    api: &Api<'_>,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<()> {
    let operation = if options.positional.is_empty() {
        String::new()
    } else {
        options.positional.remove(0)
    };
    // Validate the entire command before any read, prompt or mutation.
    let mut user = None;
    let mut supplied_name = None;
    let mut id = None;
    match (kind, operation.as_str()) {
        ("user", "" | "list") => {}
        ("user", "show") | ("device", "show" | "delete") => id = optional_id(&mut options)?,
        ("user", "add") => {
            if options.positional.len() > 1 {
                return Err(USAGE);
            }
            supplied_name = options.positional.pop();
        }
        ("user", "remove") => id = options.take("--id"),
        ("device", "add") => {
            user = options.take("--user");
            supplied_name = options.take("--name");
        }
        _ => return Err(USAGE),
    }
    options.finish()?;
    for value in [&id, &user].into_iter().flatten() {
        valid_id(value)?;
    }
    if supplied_name.as_ref().is_some_and(|n| {
        n.trim() != n || n.is_empty() || n.len() > 128 || n.chars().any(char::is_control)
    }) {
        return Err("invalid name");
    }
    let mut ui = Ui { api, input, out };
    match (kind, operation.as_str()) {
        ("user", "") => ui.home(),
        ("user", "list") => ui.user_list(),
        ("user", "show") => {
            if let Some((user, _)) = ui.select_user(id.as_deref())? {
                ui.user_menu(&user.id)?;
            }
            Ok(())
        }
        ("user", "add") => ui.add_user(supplied_name),
        ("user", "remove") => {
            if let Some((user, revision)) = ui.select_user(id.as_deref())? {
                ui.remove_user(user, revision)?;
            }
            Ok(())
        }
        ("device", "show" | "delete") => {
            if let Some((user, device, revision)) = ui.find_device(id.as_deref())? {
                if operation == "delete" {
                    ui.remove_device(&user, &device, revision)?;
                } else {
                    ui.device_menu(&device.id)?;
                }
            }
            Ok(())
        }
        ("device", "add") => {
            let Some((user, revision)) = ui.select_user(user.as_deref())? else {
                return Ok(());
            };
            let device_name = match supplied_name {
                Some(value) => value,
                None => match name(ui.input, ui.out, "Device name: ")? {
                    Some(value) => value,
                    None => return Ok(()),
                },
            };
            let id = ui.create_device(&user, &device_name, revision)?;
            ui.device_menu(&id)
        }
        _ => Err(USAGE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    #[test]
    fn deletion_uses_displayed_revision_and_never_retries_a_conflict() {
        let calls = RefCell::new(Vec::new());
        let api = |method: &str, path: &str, revision: Option<u64>, _: &[u8]| {
            calls
                .borrow_mut()
                .push((method.to_owned(), path.to_owned(), revision));
            Ok(if method == "GET" {
                Response { status:200, generation:Some(7), is_config:false, body:br#"{"users":[{"id":"u1","name":"Alice","suspended":false,"devices":[{"id":"d1","metadata":{"name":"laptop"}}]}]}"#.to_vec() }
            } else {
                Response::error(412, "revision_conflict")
            })
        };
        let mut out = Vec::new();
        assert!(
            run(
                "device",
                Options::parse(&["delete".into(), "d1".into()]).unwrap(),
                &api,
                &mut std::io::Cursor::new("y\n"),
                &mut out
            )
            .is_err()
        );
        assert_eq!(
            *calls.borrow(),
            vec![
                ("GET".into(), "/api/v1/users".into(), None),
                (
                    "DELETE".into(),
                    "/api/v1/users/u1/devices/d1".into(),
                    Some(7)
                )
            ]
        );
        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("laptop (d1) from user Alice (u1)"));
        assert!(output.contains("revision_conflict"));
    }
}
