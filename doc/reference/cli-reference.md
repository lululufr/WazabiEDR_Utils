# Référence du CLI `wedr-plugin`

Chaque sous-commande et flag de `target/release/wedr-plugin.exe`. Pour des exemples pas à pas,
voir [`managing-plugins.md`](../usage/managing-plugins.md).

## Conventions communes

- Le dossier de manifests par défaut est `%ProgramData%\WazabiEDR\plugins`.
- La plupart des sous-commandes acceptent `--dir <chemin>` pour le surcharger ; `enroll` utilise
  `--out-dir <chemin>` pour la même chose.
- Toute écriture dans le dossier par défaut nécessite les droits **Administrateur** (ACL NTFS).
- Codes de sortie : `0` = succès, `1` = échec opérationnel, `2` = erreur d'arguments.

## `enroll`

Enregistre un plugin. Écrit un nouveau fichier manifest.

```text
wedr-plugin enroll <BINARY>
                   --name <NAME>
                   --vendor <VENDOR>
                   [--signer "CN=..."]
                   [--allow-unsigned]
                   [--auto-launch]
                   [--out-dir <DIR>]
```

| Arg / flag | Requis | Signification |
|---|---|---|
| `<BINARY>` | oui | Chemin du binaire du plugin. Résolu via `canonicalize`. |
| `--name <NAME>` | oui | Nom lisible du plugin (texte libre). |
| `--vendor <VENDOR>` | oui | Auteur / organisation (texte libre). |
| `--signer "<DN>"` | l'un des deux | DN du sujet Authenticode. Impose à l'agent de vérifier la signature. |
| `--allow-unsigned` | l'un des deux | Ignore l'exigence de signature ; épinglage par SHA-256 seul. |
| `--auto-launch` | non | L'agent lance ce plugin au démarrage et le relance après crash (backoff, plafond 60 s). |
| `--out-dir <DIR>` | non | Surcharge le dossier de sortie. |

Exactement un de `--signer` / `--allow-unsigned` doit être passé, sinon l'outil refuse.

## `update`

Re-hash le binaire et rafraîchit `expected_sha256`. Sans `<BINARY>`, hashe ce qui se trouve à
`expected_path` ; avec `<BINARY>`, réécrit aussi `expected_path`.

```text
wedr-plugin update <PLUGIN_ID> [<BINARY>] [--auto-launch | --no-auto-launch] [--dir <DIR>]
```

| Arg / flag | Signification |
|---|---|
| `<PLUGIN_ID>` | UUID imprimé par `enroll`. Requis. |
| `<BINARY>` | Nouveau chemin. Optionnel — sinon `expected_path` est réutilisé. |
| `--auto-launch` / `--no-auto-launch` | Bascule le drapeau du superviseur sans rebuild. |
| `--dir <DIR>` | Surcharge le dossier de manifests. |

Sort sur « manifest already up-to-date » si le nouveau SHA correspond à l'ancien.

## `list`

Résumé tabulaire de tous les manifests. Colonnes : `plugin_id`, `name` (tronqué à 30 car.),
`revoked`, `vendor`. Trié par `plugin_id`.

```text
wedr-plugin list [--dir <DIR>]
```

## `show`

Affiche un manifest (JSON ré-sérialisé, donc lisible même si le fichier a été aplati à la main).

```text
wedr-plugin show <PLUGIN_ID> [--dir <DIR>]
```

## `doctor`

Détection de dérive sur tous les manifests. Pour chacun : validité du schéma → existence du
binaire → correspondance du SHA-256 → drapeau `revoked`. Préfixes `✓` / `⚠` / `✗`. **Code de
sortie ≠ 0** si un plugin est malsain → idéal en tâche planifiée.

```text
wedr-plugin doctor [--dir <DIR>]
```

## `path`

Imprime le dossier de manifests (le défaut, ou `--dir`).

```text
wedr-plugin path [--dir <DIR>]
```

## `revoke` / `unrevoke`

Bascule le champ `revoked`. Pris en compte par hot-reload en ~5 s. **Les sessions existantes ne
sont pas terminées** — seules les nouvelles connexions sont affectées.

```text
wedr-plugin revoke   <PLUGIN_ID> [--dir <DIR>]
wedr-plugin unrevoke <PLUGIN_ID> [--dir <DIR>]
```

## `auto-launch` / `no-auto-launch`

Bascule le drapeau `auto_launch`. Le superviseur de l'agent le lit **au démarrage seulement** —
redémarrer l'agent pour prise d'effet.

```text
wedr-plugin auto-launch    <PLUGIN_ID> [--dir <DIR>]
wedr-plugin no-auto-launch <PLUGIN_ID> [--dir <DIR>]
```

## `remove`

Supprime le fichier manifest. **Aucune annulation.** Pour désactiver temporairement, préférer
`revoke`.

```text
wedr-plugin remove <PLUGIN_ID> [--dir <DIR>]
```

## `--help` / `-h` / `help`

Affiche l'aide et sort avec le code 0.

## Codes de sortie

| Code | Signification |
|---|---|
| 0 | Succès. |
| 1 | Échec opérationnel (I/O, validation…). |
| 2 | Mauvais arguments (requis manquant, flag inconnu). |
