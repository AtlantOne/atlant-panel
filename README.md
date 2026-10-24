# Atlant Panel

Independent web panel, administration CLI and privileged helper for
[Atlant Core](https://github.com/AtlantOne/atlant-core).

The management application is in `management/`. It uses Python's standard
library. The VPN engine is a separate service; installing the panel does not
make its public management API safe to expose without protection.

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

Certificates protect panel/subscription HTTPS, not VPN protocol authentication.
Only use real deployments after reviewing the installer and configuration.

Original panel/CLI/helper sources are GPL-3.0-only; see `LICENSE` and
`management/LICENSING.md`. The separate Apache-2.0 certificate-agent sources live
in the core repository; distributions must include corresponding source and
dependency notices. The QR encoder retains its MIT license notice.
