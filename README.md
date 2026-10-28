# Atlant Panel

Atlant Panel manages [Atlant Core](https://github.com/AtlantOne/atlant-core)
through a web interface, with an administration CLI for installation and panel
settings. The VPN engine runs as a separate service, so you can use it with or
without the panel.

Manage listeners, users and subscriptions in one place, set subscription traffic
quotas and expiry dates, and share connection links or QR codes. The interface
supports English, Russian and Chinese, with light and dark themes and a live
log viewer. Backups are created when you request them.

The installed `atlant` CLI handles panel access, credentials, port settings,
and HTTPS certificates for the panel and subscription links. VPN authentication
continues to use REALITY; these HTTPS certificates serve the management layer.
The management application lives in `management/` and uses Python's standard library.

## Development

```sh
cd management
python -m unittest discover -p 'test_*.py'
```

See `management/README.md` for commands. Installed administrators use `atlant`.
Panel passwords, TLS keys, state databases and backup archives are not source
files and must never be committed.

The certificate agent is built from the matching core repository:

```sh
go -C ../atlant-core/shared build -trimpath -o ../../atlant-panel/artifacts/atlant-cert-agent ./cmd/atlant-cert-agent
```

Deployment and certificate setup are covered in `management/README.md` and
the installation guides in `docs/`. Keep the core management API on loopback;
remote administration should go through the panel or a protected SSH tunnel.

Original panel/CLI/helper sources are GPL-3.0-only; see `LICENSE` and
`management/LICENSING.md`. The separate Apache-2.0 certificate-agent sources live
in the core repository; distributions must include corresponding source and
dependency notices. The QR encoder retains its MIT license notice.
