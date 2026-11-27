use super::{CommandHelp, OptionHelp};

const INSTALL_DIR: OptionHelp = (
    "--install-dir PATH",
    "Installation base. Defaults to the running installed binary's base, or /opt/wgfeel for a downloaded binary.",
);
const STATE: OptionHelp = (
    "--state-dir PATH",
    "Local state directory. Use the installed instance's state directory or an explicitly provisioned absolute path.",
);
const ROOT: OptionHelp = (
    "--root ABS",
    "Stage filesystem paths below this absolute root. Requires --no-start or --dry-run; defaults to /.",
);
const DRY: OptionHelp = (
    "--dry-run",
    "Preview the operation without writing files or controlling services.",
);
const ENDPOINT: OptionHelp = (
    "--endpoint ADDRESS",
    "Advertised address. Main takes IP:port or [IPv6]:port. Child takes a bare IPv4 or IPv6 address. Repeat in preference order.",
);

pub(super) const CONNECTION: &[OptionHelp] = &[
    (
        "--profile PATH",
        "Use an existing private administrator profile for remote access over WireGuard. Cannot be combined with --socket or --credential-file.",
    ),
    (
        "--socket PATH",
        "Use a local Management API socket; requires --credential-file.",
    ),
    (
        "--credential-file PATH",
        "Read the administrator credential from an owned regular file with mode 0600; requires --socket.",
    ),
];

fn command(
    name: &'static str,
    arguments: &'static str,
    description: &'static str,
    options: &[OptionHelp],
    examples: &'static [&'static str],
) -> CommandHelp {
    CommandHelp {
        name,
        arguments,
        description,
        options: options.to_vec(),
        examples,
        administrative: false,
    }
}

pub(super) fn commands() -> Vec<CommandHelp> {
    let mut pages = vec![
        command(
            "install",
            "[--control main|child] [OPTIONS]",
            "Install one wgfeel executable, one wgfeel.service, manuals, completions and protected state under instance/. Main can also carry user traffic. Run without arguments for the interactive menus. On main, choose the traffic mode and both ports. A child stays stopped until join. Existing state is preserved; use update for an existing installation.",
            &[
                (
                    "--control main|child",
                    "Control capability; required for noninteractive installation.",
                ),
                (
                    "--traffic entry|relay|off",
                    "Main's user-traffic capability; default entry. Child traffic policy is assigned by main.",
                ),
                (
                    "--port PORT",
                    "WireGuard UDP port on main, also assigned to children at join. Default 51820.",
                ),
                ENDPOINT,
                (
                    "--listen-ip IP",
                    "UDP bind IP. Defaults to the wildcard address matching the endpoint family.",
                ),
                (
                    "--id ID",
                    "Unique persistent node name. Defaults to main or the child’s short hostname. If the hostname is unavailable or invalid, a child gets a generated ID.",
                ),
                (
                    "--api-port PORT",
                    "External REST HTTP/TCP port on main; default 9280. Change it later with wgfeel api port PORT.",
                ),
                (
                    "--api-listen-ip IP",
                    "HTTP bind IP on main; default 127.0.0.1.",
                ),
                INSTALL_DIR,
                ROOT,
                DRY,
                (
                    "--no-start",
                    "Keep the service stopped after installation and after child enrollment.",
                ),
            ],
            &[
                "wgfeel install --control main --traffic entry \\\n  --endpoint 192.0.2.1:51820 --api-port 9280",
                "wgfeel install --control child --endpoint 192.0.2.2",
            ],
        ),
        command(
            "update",
            "[OPTIONS]",
            "Replace the installed executable and refresh its manual and shell completions from the newly copied binary. Preserve configuration, keys and service settings; retain the previous binary and restart the previously active service. No downloads are performed.",
            &[
                INSTALL_DIR,
                ROOT,
                DRY,
                (
                    "--no-start",
                    "Skip service control; the instance must be stopped.",
                ),
            ],
            &["./wgfeel.new update --dry-run", "./wgfeel.new update"],
        ),
        command(
            "uninstall",
            "[OPTIONS]",
            "Remove the receipt-owned service, executable and command resources. Keep state and keys unless purge is explicitly confirmed. Preview first with --dry-run.",
            &[
                INSTALL_DIR,
                DRY,
                (
                    "--purge",
                    "Also delete recorded configuration and state; requires confirmation.",
                ),
                (
                    "--confirm wgfeel",
                    "Noninteractive confirmation for --purge.",
                ),
            ],
            &[
                "wgfeel uninstall --dry-run",
                "wgfeel uninstall",
                "wgfeel uninstall --purge --confirm wgfeel",
            ],
        ),
        command(
            "api port",
            "[PORT] [OPTIONS]",
            "Show or change the external REST HTTP listener port on this main. The running service opens the new listener before saving the setting and closing the old one. A stopped service saves the setting for its next start. Does not change WireGuard, device profiles or keys. Only the local owner can perform this operation.",
            &[
                STATE,
                INSTALL_DIR,
                (
                    "PORT",
                    "Optional TCP port, 1..65535. Omit to show the current HTTP address.",
                ),
            ],
            &["wgfeel api port", "wgfeel api port 8081"],
        ),
        command(
            "state-check",
            "--state-dir PATH",
            "Read committed local child forwarding state and print its public summary. Main authority state uses a different format. Does not print private keys.",
            &[STATE],
            &["wgfeel state-check --state-dir /opt/wgfeel/instance/state"],
        ),
        command(
            "--build-info",
            "",
            "Print the executable name and package version without opening state or contacting a service.",
            &[],
            &["wgfeel --build-info"],
        ),
        command(
            "completions",
            "SHELL",
            "Print shell integration for Bash or Zsh. Source it in the matching shell after enabling its standard completion system. Static commands require no connection. User, device and node IDs are queried using the current administrator connection and permissions; unavailable data produces no dynamic suggestions.",
            &[("SHELL", "bash or zsh.")],
            &[
                "source <(wgfeel completions bash)",
                "source <(wgfeel completions zsh)",
            ],
        ),
    ];
    pages.extend(instance());
    pages.extend(administration());
    pages
}

fn instance() -> Vec<CommandHelp> {
    vec![
        command(
            "init",
            "--control main|child [OPTIONS]",
            "Initialize protected state for the selected control capability. Main owns authoritative configuration and defaults to entry traffic. Child starts unbound. Run the wgfeel join command issued by main to receive its configuration. Existing state is never overwritten.",
            &[
                (
                    "--control main|child",
                    "Required control capability. Only main can write authoritative configuration.",
                ),
                (
                    "--state-dir PATH",
                    "Required absolute local state directory.",
                ),
                (
                    "--id ID",
                    "Node identity; required for child initialization.",
                ),
                (
                    "--traffic entry|relay|off",
                    "Main traffic capability. Default: entry. Child policy is assigned by main.",
                ),
                (
                    "--profile PATH",
                    "Required private administrator profile destination for main.",
                ),
                (
                    "--listen IP:PORT",
                    "Required main WireGuard UDP bind address. An advertised --endpoint is also required, including for a concrete bind address.",
                ),
                (
                    "--endpoint IP:PORT",
                    "Required advertised main unicast IP and UDP port. IPv6 uses [address]:port. Child enrollment discovers its endpoints through join.",
                ),
                (
                    "--api-port PORT",
                    "Enable the independent external HTTP API on main. Omitted means disabled for this low-level command.",
                ),
                (
                    "--api-listen-ip IP",
                    "HTTP bind address on main; default 127.0.0.1. Requires --api-port.",
                ),
            ],
            &[
                "wgfeel init --control main --traffic entry \\\n  --state-dir /srv/wgfeel/state --profile /srv/wgfeel/admin.json \\\n  --listen 0.0.0.0:51820 --endpoint 192.0.2.1:51820 --api-port 9280",
                "wgfeel init --control child --state-dir /srv/wgfeel/state --id child1",
            ],
        ),
        command(
            "serve",
            "--control main|child --state-dir PATH [OPTIONS]",
            "Run the selected control capability in the foreground. Main uses its stored WireGuard and optional HTTP listeners. Installed children use --listen-ip and recover the assigned port from their committed binding. For a foreground child with an explicit bind address, use --listen. The executable name does not select authority.",
            &[
                (
                    "--control main|child",
                    "Required control capability; it must match the initialized state.",
                ),
                STATE,
                (
                    "--listen IP:PORT",
                    "Explicit WireGuard bind address for a manually started child.",
                ),
                (
                    "--listen-ip IP",
                    "Bind an enrolled child at its assigned port.",
                ),
            ],
            &[
                "wgfeel serve --control main --state-dir /srv/wgfeel/state",
                "wgfeel serve --control child --state-dir /srv/wgfeel/state \\\n  --listen 0.0.0.0:51820",
            ],
        ),
        command(
            "join",
            "INVITATION|--invitation-stdin [OPTIONS]",
            "Enroll the local child using a one-time invitation over service WireGuard on the shared UDP port. The installed child uses the UDP port from the invitation. Join enables and starts its service after saving configuration, unless installed with --no-start. Print main's UDP addresses immediately and progress every five seconds. Wait up to 75 seconds for durable configuration; a failed join preserves the previous binding unless replacement was committed.",
            &[
                (
                    "INVITATION",
                    "One-time URI from wgfeel node add. Prefer --invitation-stdin to keep the URI out of command arguments.",
                ),
                (
                    "--invitation-stdin",
                    "Read a single invitation line from standard input.",
                ),
                INSTALL_DIR,
                STATE,
                (
                    "--endpoint IP:PORT",
                    "Advertised child endpoint. Repeat for IPv4 and IPv6; normally discovered automatically.",
                ),
            ],
            &["wgfeel join --invitation-stdin"],
        ),
    ]
}

fn administration() -> Vec<CommandHelp> {
    let mut pages = vec![
        command(
            "user",
            "",
            "Open the interactive administration menus. Select users and devices by number; names are separate from generated IDs. The menus also provide suspension and resumption of a user's isolated network.",
            &[],
            &["wgfeel user"],
        ),
        command(
            "user list",
            "",
            "List users with their IDs, names, device counts and suspension status, then allow interactive selection. Enter 0 to return.",
            &[],
            &["wgfeel user list"],
        ),
        command(
            "user show",
            "[ID]",
            "Open a user's details and device menu. Omit ID to select a user interactively.",
            &[("ID", "Existing user ID; optional.")],
            &["wgfeel user show"],
        ),
        command(
            "user add",
            "[NAME]",
            "Create a user and its isolated network. Ask for the user name when omitted, then ask for the first device name. IDs, addresses and keys are generated. Names must be nonempty, at most 128 bytes, with no control characters or surrounding whitespace.",
            &[("NAME", "Friendly user name; quote names containing spaces.")],
            &["wgfeel user add Alice"],
        ),
        command(
            "user remove",
            "[--id ID]",
            "Display the selected user and ask for confirmation before deleting the user and its devices. Omit --id to choose interactively. Confirmation defaults to no.",
            &[("--id ID", "Existing user ID; optional.")],
            &["wgfeel user remove"],
        ),
        command(
            "device add",
            "[--user ID] [--name NAME]",
            "Create a device in the selected user's network, then open its details. Ask for any omitted user or device name. Import the generated WireGuard configuration into the device's native client.",
            &[
                (
                    "--user ID",
                    "Owner's user ID; otherwise choose interactively.",
                ),
                (
                    "--name NAME",
                    "Friendly device name; otherwise enter it interactively.",
                ),
            ],
            &["wgfeel device add"],
        ),
        command(
            "device show",
            "[ID]",
            "Open device details, including its WireGuard client configuration. Omit ID to select the owner and device interactively. The client configuration contains a private key; handle the displayed output as a secret.",
            &[("ID", "Existing device ID; optional.")],
            &["wgfeel device show"],
        ),
        command(
            "device delete",
            "[ID]",
            "Display the device and ask for confirmation before deleting it. Omit ID to select interactively. Confirmation defaults to no.",
            &[("ID", "Existing device ID; optional.")],
            &["wgfeel device delete"],
        ),
        command(
            "node list",
            "",
            "List Nodes registered with Management and their public enrollment information.",
            &[],
            &["wgfeel node list"],
        ),
        command(
            "node show",
            "ID",
            "Show public details of the selected registered Node.",
            &[("ID", "Required registered Node ID.")],
            &[],
        ),
        command(
            "node add",
            "[OPTIONS]",
            "Create a one-time invitation and print the main endpoints, child UDP port and wgfeel join command. Main fixes the traffic mode in the invitation; the child cannot override it. Re-enrolling an existing child requires its current mode. Treat the invitation as a credential.",
            &[
                (
                    "--traffic entry|relay|off",
                    "Child traffic capability. Default: entry. Relay carries ciphertext without tenant keys; off carries control traffic only.",
                ),
                (
                    "--revision NUMBER",
                    "Require this positive configuration revision when issuing the invitation. Otherwise read the current revision first. An invitation does not reserve a revision for later enrollment.",
                ),
            ],
            &["wgfeel node add", "wgfeel node add --traffic relay"],
        ),
        command(
            "node delete",
            "ID [--revision NUMBER]",
            "Display the Node and ask for confirmation before removing it from the desired configuration. Confirmation defaults to no.",
            &[
                ("ID", "Required registered Node ID."),
                (
                    "--revision NUMBER",
                    "Expected positive configuration revision; otherwise use the current revision.",
                ),
            ],
            &[],
        ),
        command(
            "config show",
            "",
            "Display the public desired Management configuration.",
            &[],
            &["wgfeel config show"],
        ),
        command(
            "config identity",
            "",
            "Display the public Management identity and enrollment information.",
            &[],
            &["wgfeel config identity"],
        ),
        command(
            "config distribution",
            "",
            "Display configuration delivery status for Nodes.",
            &[],
            &["wgfeel config distribution"],
        ),
        command(
            "token rotate",
            "[--revision NUMBER]",
            "Revoke the old administrator token and print the new token once. Available only through installed local administration, without --profile, --socket or --credential-file. Preserve the new token securely.",
            &[(
                "--revision NUMBER",
                "Expected positive configuration revision; otherwise use the current revision.",
            )],
            &["wgfeel token rotate"],
        ),
    ];
    for page in &mut pages {
        page.administrative = true;
    }
    pages
}
