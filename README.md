# WazabiEDR_Utils

Operator-side tooling for [WazabiEDR](../WazabiEDR_Doc/README.md).

Currently ships **one** binary:

| binary        | purpose                                              |
|---------------|------------------------------------------------------|
| `wedr-plugin` | enrol / list / show / doctor / update / revoke / remove plugins |

## Build & quick reference

```powershell
cargo build --release
.\target\release\wedr-plugin.exe --help
```

The default manifest directory is `%ProgramData%\WazabiEDR\plugins\`.
Writing to it requires Administrator. The agent **hot-reloads** that
directory every 5 s — no agent restart is needed after any operation.

## Documentation

All documentation lives in **[../WazabiEDR_Doc/](../WazabiEDR_Doc/README.md)**.
Highlights for `wedr-plugin`:

- [Managing plugins (operator guide)](../WazabiEDR_Doc/usage/managing-plugins.md) — every subcommand with examples
- [CLI reference (every flag)](../WazabiEDR_Doc/reference/cli-reference.md)
- [Enrolment internals](../WazabiEDR_Doc/architecture/enrollment-internals.md) — what `enroll` does step by step
- [Plugin manifest store](../WazabiEDR_Doc/architecture/plugin-manifest.md) — what these manifests are and how the agent reads them
