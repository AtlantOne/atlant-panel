# Atlant Control — development source

Independent process, authored for Atlant under GPL-3.0-only (see management/LICENSE).
No 3x-ui source code is included. This is **not yet a production replacement**
for the bot or the existing management interface. Do not replace either with
this development service. The completion checklist is maintained in
`docs/CONTROL_PANEL_EXECUTION_RU.md`.

## Implemented boundary

The browser calls the control service, not the VPN administrative API. The
existing `Manager` is shared with `atlantctl`: validation, safety backups,
service helper and write auditing use the same operation path. API credentials
stay on the server. The service stores no client profiles in browser storage.

One local administrator with login and password, scrypt password hash, opaque HttpOnly/SameSite sessions,
CSRF tokens, exact Host/Origin checks, bounded login attempts, bounded HTTP
workers, absolute/idle session expiry and session-bound single-use write
confirmations are implemented. Sessions are in RAM and invalidated by restart.
No claim of complete security review or production readiness is made.

English, Russian and Simplified Chinese catalogs are shared with the CLI.
UI selection persists in local storage; command names and protocol fields stay
unchanged. User-supplied names are not translated. Passwords, API credentials
and access links are not persisted in local storage.

## Local development

Use an existing private management-client configuration containing the loopback
`api_url`, `api_key`, `state_dir` and optional `service_helper`. Add:

```json
"panel": {
  "listen": "127.0.0.1",
  "port": 9090,
  "origin": "http://127.0.0.1:9090",
  "state_dir": "/var/lib/atlant-control"
}
```

Set the password interactively, never in command-line arguments:

```sh
python3 management/atlant_control.py set-password --config /private/client.json
python3 management/atlant_control.py serve --config /private/client.json
python3 management/atlantctl.py --lang zh help
python3 management/atlantctl.py --lang ru status
```

Keep the configuration and credentials private. `credentials.json` requires
mode 0600 on POSIX. The installed menu is `sudo atlant` (or `sudo atlant menu`).
`sudo atlant panelurl` displays the full private panel URL. Its 192-bit random
path is generated once and saved privately, not regenerated on restart.
The full saved URL is also printed automatically above the interactive menu.
Panel settings has a quick port editor, address/HTTPS, terminal credential change,
certificate status, settings backups and an explicit panel-only restart. Saving
a different port updates the origin together with it, retaining the private path.
The displayed saved URL is not a claim that the new listener is already active;
apply/restart the panel and check access. The VPN service is not restarted.
The unprefixed browser routes return 404; peer RPC and loopback health are separate.
The URL is not printed to the production service log. It is an extra entry barrier,
not a substitute for HTTPS and login/password authentication.

Only terminal commands can change credentials: `sudo atlant panelpassword`, or
the source recovery command shown above. The command prompts for login and the
new password twice without putting the password in process arguments or echoing
it. The running panel reloads the private credential file and revokes previous
sessions and pending confirmations on the next browser request. The web password
form and its mutation endpoint have been removed. Browser sessions cannot invoke
the terminal-only password command through the operations API.

Panel address/TLS selection now uses its own revisioned private settings file,
forms and CLI `panelsettings` / `panelset` / `panelbackups` / `panelrestore`.
Manual pairs and already-issued automatic certificates are validated before
prepare and commit. Changes activate on a planned panel restart, not a VPN
restart. CLI/SSH recovery remains necessary when changing the public address.

An optional `service_socket` selects the restricted Linux root helper instead
of sudo. Peer UIDs are checked by both ends; only the configured Atlant unit and
four configuration fields are accepted. See `docs/SERVICE_HELPER_RU.md`.
The helper/systemd templates are not yet installed or accepted on the VDS.
First-install `plan`/`install` tooling is now in `management/install_control.py`;
see `docs/CONTROL_INSTALL_RU.md` for its explicit boundaries and recovery gaps.
`certservice` controls the separate issuer through the socket helper. Neither
installation nor saving a job starts certificate issuance implicitly.

Plaintext is refused for non-loopback origins/listeners. Optional `cert_file`
and `key_file` in `panel` enable a standalone TLS listener. The certificate must
match the hostname/IP in `panel.origin` and be currently valid. A local in-memory
TLS handshake validates it before use; it does not establish public CA trust.
Valid replacement files are reloaded every 30 seconds without restarting;
an invalid/mismatched replacement retains the last valid context and reports an
error through authenticated `/control/certificate`. This is external/manual
rotation for manual mode. The new independent `atlant-cert-agent` implements
IP/domain ACME issuance and renewal through the shared certificate engine;
see `docs/CERTIFICATE_AGENT_RU.md`. The panel can consume its atomic bundle,
validate the CA/profile context, and report unavailable/stale issuer status.
Typed job-management forms and CLI mutations now share the native validator,
revision checks and private backups. `atlantctl menu` provides interactive
certificate management without writing JSON. `certbackups` / `certrestore` expose
settings recovery in the panel and CLI. These are not private-key backups.
Installation/migration and the remaining certificate lifecycle operations are
still in progress; do not treat this as an installed production service.
`atlantctl paneltls` validates local
files without needing the core API; its output is explicitly not live status.
Do not point
this developer service at the production port used by x-ui or subscriptions.

## Typed UI now implemented

Users have a per-row editor for enabled state, fractional traffic quota, expiry,
IP limit and note; unchanged fields are not reset. Accounts on shared quotas
edit their subscription limit rather than silently editing an unused legacy cap.
Subscriptions have metadata/quota editors, membership and endpoint tables, and
an existing-account picker. `subattach ID NAME ENDPOINT_INDEX` is backed by a
single server transaction for membership and exported profile; foreign-server
endpoints and rebinding to another subscription are rejected. Current local
credentials are used after rekey rather than stale embedded profile keys.

Overview, settings, certificate status, nodes, logs and backups use normal
labels/tables/forms, not JSON dumps. Explicit system/light/dark preference is
stored locally; blocked local storage does not break the controls. Command
payloads are still JSON internally, as expected for an API, but are not the UI.

SQLite client groups, per-row actions, selection/bulk operations and tabbed
editors are implemented. Subscription endpoint forms use nodeadd/nodeset/nodedel
and do not disclose the existing remote account key. PUT subscriptions now
requires the revision returned by GET; stale writes return HTTP 409. Deploy the
core and administrative tools together. Group membership also uses revisions.
Quota-node enrollment and scope editing use separate limited node credentials;
these are not full remote-server administration credentials.

The standalone demo remains disposable and is not a substitute for production
verification. Read-only reference inspection succeeded, but the subsequent local
preview attempt reported disabled browser access. Rendered/interactive visual
acceptance of the new implementation remains outstanding.

For a stable local preview login across restarts, use
`python management/atlant_control_demo.py --port 9090 --state-dir /private/preview-state`.
The initial generated password is shown once, and only its salted hash is stored.
Password changes persist in that private state. VPN data remains disposable; this
mode never connects to a production server or executes service helpers. Preview
credentials/settings are development state, not part of a public source package.

## Still required before release

The core starts wire7 inbounds from its SQLite catalog and exposes authenticated
`/api/inbounds` GET/POST/PUT/DELETE and POST `/api/inbounds/apply`. Saved settings
are separate from the private applied snapshot used at boot. Writes require the
catalog revision and a complete typed settings object; safety snapshots precede
mutations. Apply replaces listeners (disconnecting sessions), restores the previous
runtime if startup or applied-snapshot persistence fails, and reports failure instead
of claiming the new revision is active. Referenced legacy inbounds cannot be deleted.
The web editor and CLI commands `inboundcreate`, `inboundset`, `inbounddelete` and
`inboundapply` share these operations. The interactive CLI has the same basic forms.
Native mode rejects global connection-settings updates rather than reporting an
unapplied SNI change as successful. Native subscribers have scoped inbound
references and one quota. `submigration` previews migration of legacy profiles;
`submigrate` converts explicitly selected, unambiguous local profiles while
preserving credentials, links and accounting. Shared owners, ambiguous endpoint
matches and conflicting quotas are blocked, not guessed. Unmigrated legacy
accounts retain their legacy access model until resolved.

### Connecting panels

Both panels need verified HTTPS origins. On the controller create an invitation
with `peerinvite` (explicit secret display); on the follower use the interactive
Servers menu to paste it. Avoid passing invitation links through shell arguments
or storing them in shell history. Approve the pending panel ID and URL on the
controller, then finish on the follower. Invitations expire in five minutes.
Panel-to-panel credentials are separate from core API keys. TLS validates the
remote host and the authenticated request has a timestamp and persistent replay
protection. This is TLS plus directional HMAC credentials, not mTLS.

The default scope is read-only status and the follower's inbound catalog.
The follower can explicitly grant/revoke inbound mutations using the Servers UI
or `peergrant CONTROLLER_ID true|false`. This permission includes creating,
editing, deleting and applying **all inbounds on that follower**, including
disconnections when listeners are applied. It does not authorize shell commands,
service management, certificates, subscriptions or access to other panels.
The controller uses the same typed inbound editor and interactive CLI forms.

`peerexecute FOLLOWER_ID 'inboundapply REVISION'` is the non-interactive form.
Each operation has a durable ID. `peerjobs FOLLOWER_ID` lists operations and
`peerretry FOLLOWER_ID REQUEST_ID` retrieves/retries the **same** intent. A lost
response cannot automatically duplicate a completed mutation. A crash between
the core change and recording its result remains explicitly uncertain; inspect
the catalog/audit before making a fresh revision-checked operation. There is no
claim of an atomic transaction spanning the panel database and core database.
Requests expire after 24 hours. Journals are bounded; retention is two days.

Revocation is local first, then best-effort notification of the other panel.
An offline remote must also be revoked there; the UI reports this explicitly.
Re-pairing does not inherit old write permissions. Private safety backups contain
credentials, must never be published, and are not offered as online key rollback.
Remote subscriber provisioning, quota wiring and in-place credential rotation
remain release requirements; inbound management alone is not multi-VDS completion.

`peersync FOLLOWER_ID` explicitly imports the follower's **applied** public
catalog into the controller core. `remotecatalogs` displays the saved snapshots.
The pair identity and stable core identity are bound; rollback of a revision,
different content at the same revision, importing the controller itself, and
rebinding a core identity to another pair are rejected. Snapshots contain no
server private keys and are included in complete SQLite recovery, not JSON
account exports. No remote subscription reference becomes usable merely by
syncing a catalog: scoped account provisioning and quota binding must follow.

The core now has a private `/api/control/remote-account` primitive for that next
step. It stores a separate scoped account and a dedicated HTTPS quota route,
without creating another local quota ledger. Missing worker/credit denies
traffic. Policy, credentials and route survive complete SQLite recovery; node
tokens are private database content, not encrypted-at-rest vault entries.
This primitive is not yet connected to the panel-pair provisioning workflow or
subscriber editor. Inbound-write permission has **not** been silently expanded
to grant subscriber provisioning. Do not treat it as a finished multi-VDS wizard.

- Complete operation parity and installation flows; native listener management
  needs new server capabilities. Bulk actions, quota enrollment/scope editing
  and subscription endpoint editing are implemented, not the entire node lifecycle.
- Multi-server administration distinct from the already working shared quota.
- Complete certificate job management and installation/migration. The independent
  ACME agent and panel consumption are implemented; existing `tlsset` still
  controls subscription certificates only. Neither modifies REALITY.
- Installation/uninstallation and least-privilege systemd packaging, release
  update verification/rollback, security/load review.
- Complete Android/Windows localization and administration entry points.
- Rendered layout, accessibility and end-to-end acceptance tests in three
  languages. Existing unit/HTTP tests alone are not this acceptance.

## Tests

```sh
python3 -m unittest discover -s management -p 'test_*.py'
go run tests/core-language/main.go
```
