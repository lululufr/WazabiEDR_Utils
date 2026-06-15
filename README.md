# WazabiEDR_Utils

Outillage opérateur de l'EDR **WazabiEDR**. Livre **un** binaire :

| Binaire | Rôle |
|---|---|
| `wedr-plugin` | enroll / list / show / doctor / update / revoke / auto-launch / remove des plugins |

`wedr-plugin` écrit et maintient les **manifests** de plugins sous
`%ProgramData%\WazabiEDR\plugins\` — la fiche signalétique de chaque plugin autorisé à se
connecter à l'agent. L'agent **recharge à chaud** ce dossier toutes les 5 s : aucun redémarrage
n'est nécessaire après une opération.

## Build & aperçu rapide

```powershell
cargo build --release
.\target\release\wedr-plugin.exe --help
```

Écrire dans le dossier par défaut nécessite les droits Administrateur.

## Documentation

Toute la documentation vit désormais **dans ce dépôt** (plus de dépôt `WazabiEDR_Doc`).

- 📐 **[ARCHITECTURE.md](ARCHITECTURE.md)** — manifest, anatomie du CLI, `enroll` étape par étape,
  crypto sans dépendance, hot-reload côté agent.
- 🧑‍💻 [doc/usage/managing-plugins.md](doc/usage/managing-plugins.md) — chaque commande avec exemples.
- 📑 [doc/reference/cli-reference.md](doc/reference/cli-reference.md) — chaque flag.

Voir aussi : [`WazabiEDR_PluginSDK`](../WazabiEDR_PluginSDK/) (écrire un plugin) et
[`WazabiEDR_Agent`](../WazabiEDR_Agent/) (la vérification d'identité côté agent).
