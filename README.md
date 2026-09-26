# bitbucket-mcp

**MCP server for Bitbucket Cloud**: repositories, pull requests, branches, tags, commits, diffs, files and pipelines, for Claude (claude.ai, Claude Desktop, Claude Code, mobile) and other AI agents that speak the Model Context Protocol.

It ships `bb`, a small Bitbucket Cloud command-line client written in standard-library Python, and `bb mcp-serve`, which serves that client over streamable HTTP as two MCP tools behind a bearer secret.

## Features

Two tools. Each takes `{"args": [...]}`: the words that would follow `bb` on a command line.

| Tool | What it runs |
|---|---|
| `bb_read` | Read-only commands. Nothing it runs changes anything. |
| `bb_write` | Commands that change something. Mark it "ask before use" in your client. |

Read-only commands (`bb_read`):

- `whoami`, `scopes`
- `repo get`, `repo list [WORKSPACE]`
- `branch list [--name TEXT]`, `branch get NAME`
- `tag list`, `tag get NAME`
- `commit get HASH`, `commit list [REVISION] [--path P]`
- `diff SPEC`, `diffstat SPEC`
- `file get REF PATH`, `file list REF [PATH]`
- `pr list [--state …] [--author …] [--source B] [--dest B] [--title …]`
- `pr get | diff | diffstat | commits | activity | comments | tasks | statuses ID`
- `pipeline list [--branch B]`, `pipeline get UUID`, `pipeline steps UUID`, `pipeline log UUID STEP_UUID`
- `api GET PATH [--query k=v] [--raw] [--paginate]`

Commands that change something (`bb_write`):

- `branch create NAME --from REF`, `branch delete NAME`
- `tag create NAME --from REF [--message …]`, `tag delete NAME`
- `pr create`, `pr update`, `pr comment`, `pr comment-edit`, `pr comment-delete`
- `pr task-create`, `pr task-update`, `pr task-delete`
- `pr approve`, `pr unapprove`, `pr request-changes`, `pr remove-request-changes`, `pr decline`
- `pr merge ID [--strategy squash|merge_commit|fast_forward]`
- `pipeline run --branch B [--pattern NAME]`, `pipeline stop UUID`
- `api POST|PUT|DELETE PATH [--data JSON]`

Every write accepts `--dry-run`. Output is JSON; `--brief` gives one line per item; `--all` follows every page.

## Requirements

- Linux or macOS with Python 3.8 or newer (standard library only)
- A Bitbucket Cloud account and an Atlassian API token with Bitbucket scopes
- Optional: `cloudflared`, to reach the server from claude.ai and mobile

## Install

```sh
git clone <this repository's URL> bitbucket-mcp
cd bitbucket-mcp
pipx install .        # or: python3 -m pip install --user .
```

This installs two commands: `bb` and `bb-auth`.

Store the API token (create it at <https://id.atlassian.com/manage-profile/security/api-tokens>, "Create API token with scopes", app Bitbucket). `bb-auth` asks for your Atlassian email and the token, writes them to `~/.netrc` (mode 600) under `machine api.bitbucket.org`, and checks them. The token is never printed.

```sh
bb-auth
bb whoami --brief
```

## Configure

All settings are environment variables and all are optional. See [config.example.env](config.example.env).

| Variable | Default | Meaning |
|---|---|---|
| `BB_DEFAULT_REPO` | none | Repository used when a command has no `--repo`, as `WORKSPACE/SLUG` |
| `BB_MCP_BIND` | `127.0.0.1` | Address the MCP server listens on. Keep it on the loopback interface |
| `BB_MCP_PORT` | `8765` | Port the MCP server listens on (`--port` overrides it) |
| `BB_MCP_SECRET_FILE` | `~/.config/bb/mcp-secret` | File holding the bearer secret (mode 600) |
| `BB_MCP_PUBLIC_HOSTS` | none | Comma-separated public host names that may reach the server, e.g. a tunnel hostname |

## Run

```sh
bb mcp-serve --init-secret   # create the bearer secret (prints its path only)
bb mcp-serve                 # serve on 127.0.0.1:8765
bb mcp-serve --show-header   # print "Bearer …" (only when stdout is a terminal)
bb mcp-serve --rotate-secret # replace the secret, then restart and update clients
```

As a systemd user service: copy [examples/bitbucket-mcp.service](examples/bitbucket-mcp.service) to `~/.config/systemd/user/`, set the path to `bb`, put your settings in `~/.config/bb/bitbucket-mcp.env`, then:

```sh
systemctl --user daemon-reload
systemctl --user enable --now bitbucket-mcp
journalctl --user -u bitbucket-mcp -f     # one line per request
```

## Connect to Claude

**claude.ai (web, desktop and mobile)**: Settings → Connectors → Add custom connector. URL `https://<your-public-host>/mcp`, and an `Authorization` header with the value from `bb mcp-serve --show-header`. claude.ai needs a public HTTPS URL; see the tunnel section below.

**Claude Code** on the same machine:

```sh
claude mcp add --transport http bitbucket http://127.0.0.1:8765/mcp \
  --header "Authorization: Bearer $(cat ~/.config/bb/mcp-secret)"
```

## Optional: expose over Cloudflare Tunnel

```sh
cloudflared tunnel create <TUNNEL-NAME>
cloudflared tunnel route dns <TUNNEL-NAME> <MCP-HOSTNAME>
```

Use [examples/cloudflared.yml](examples/cloudflared.yml) as the tunnel config, set `BB_MCP_PUBLIC_HOSTS=<MCP-HOSTNAME>`, and restart the service. The server itself still listens only on the loopback interface.

## Security notes

- Every request needs `Authorization: Bearer <secret>`, compared in constant time. A wrong secret gets `401`; more than 10 failures a minute from one client get `429` for 60 seconds.
- Requests whose `Host` is not `127.0.0.1:<port>`, `localhost:<port>` or a name in `BB_MCP_PUBLIC_HOSTS` get `421`.
- `/.well-known/*` answers `404` without the secret, so clients do not look for OAuth.
- The Bitbucket token is only ever sent to `https://api.bitbucket.org`. Redirects to other hosts have the `Authorization` header removed.
- Output is scrubbed of the token and the bearer secret before it is returned. Logs record the tool, the command and the exit code, never arguments' values or output.
- Through MCP, options that read local files (`--text-file`, `--data-file`, …), absolute URLs for `api`, and `--confirm-delete-repository` are refused.
- `bb_read` refuses any write, and `bb_write` refuses reads, so a client can auto-approve `bb_read` only.
- Commands run from an argument list, never through a shell, with a 90-second timeout and output capped at 100,000 characters.

## Credits

Written by Febin Micheal Antony. Uses the [Bitbucket Cloud REST API](https://developer.atlassian.com/cloud/bitbucket/rest/) and the [Model Context Protocol](https://modelcontextprotocol.io/).

## License

[MIT](LICENSE)
