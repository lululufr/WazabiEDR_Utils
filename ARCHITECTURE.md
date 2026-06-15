# Architecture de `wedr-plugin` (WazabiEDR_Utils)

> Document d'onboarding. Il s'adresse à un développeur qui sait coder **mais ne connaît rien à
> ce projet**. On part de zéro : chaque terme propre au projet (manifest, enrôlement,
> hot-reload…) est expliqué (entre parenthèses) à sa première apparition. Les chemins entre
> crochets renvoient au code (`src/...`) et sont cliquables sur GitHub.

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Le manifest : le contrat de confiance](#2-le-manifest--le-contrat-de-confiance)
3. [Anatomie du CLI](#3-anatomie-du-cli)
4. [`enroll`, étape par étape](#4-enroll-étape-par-étape)
5. [Cryptographie sans dépendance (SHA-256 & UUID)](#5-cryptographie-sans-dépendance-sha-256--uuid)
6. [Les autres sous-commandes](#6-les-autres-sous-commandes)
7. [Ce qui se passe côté agent (hot-reload)](#7-ce-qui-se-passe-côté-agent-hot-reload)
8. [Par où commencer](#8-par-où-commencer)

---

## 1. Vue d'ensemble

WazabiEDR est un **EDR** (*Endpoint Detection and Response* : système de sécurité qui surveille
les machines pour détecter les comportements malveillants). Ce dépôt fournit l'**outillage
opérateur** : un unique binaire en ligne de commande, **`wedr-plugin`**, qui sert à gérer les
**plugins**.

Un **plugin** est un programme tiers, séparé de l'agent, qui produit sa propre télémétrie
applicative et la pousse à l'agent WazabiEDR via un *named pipe* (tube nommé). Avant d'accepter
le moindre événement, l'agent doit s'assurer que le programme à l'autre bout du tube est bien le
plugin **autorisé**, et pas un imposteur. Pour cela, il consulte un **manifest** : une fiche
signalétique, écrite à l'avance, qui décrit chaque plugin autorisé (son identifiant, le chemin
attendu de son exécutable, son empreinte SHA-256, etc.).

`wedr-plugin` est l'outil qui **écrit, lit et édite ces manifests**. Son rôle se résume à :

- **enrôler** (`enroll`) un nouveau plugin → écrit un fichier manifest ;
- **maintenir** les manifests (`update`, `revoke`, `unrevoke`, `auto-launch`, `remove`) ;
- **inspecter** (`list`, `show`, `path`) et **auditer** (`doctor`).

Le binaire est volontairement **minuscule et autonome** : aucune dépendance lourde, ni même la
crate `uuid`, `sha2`, `chrono` ou `clap`. Le parsing d'arguments est fait à la main, et la
cryptographie passe directement par les API Windows **BCrypt CNG** (§5). Raison : garder l'outil
léger et sans surface d'attaque transitive, et lui permettre d'être bâti indépendamment de
l'agent. Le code complet tient dans [`src/wedr_plugin/`](src/wedr_plugin/).

```text
   opérateur (admin)                       agent WazabiEDR (tourne en service)
        │                                          │
        │  wedr-plugin enroll <bin> …              │
        ▼                                          │  hot-reload toutes les 5 s
   %ProgramData%\WazabiEDR\plugins\  ◄─────────────┘  (relit le dossier de manifests)
        └─ <plugin_id>.json   ← un fichier par plugin autorisé
```

---

## 2. Le manifest : le contrat de confiance

Le **dossier de manifests** est **le** point de contrôle de sécurité du système de plugins :
quiconque peut y écrire un fichier peut enrôler un plugin. C'est pourquoi son chemin est
**codé en dur** dans l'agent — `%ProgramData%\WazabiEDR\plugins\` (par défaut
`C:\ProgramData\WazabiEDR\plugins`) — et protégé par une **ACL** (*Access Control List* : la
liste des droits NTFS) réservant l'écriture aux Administrateurs. Le rendre configurable par un
utilisateur non privilégié contournerait l'ancrage de confiance.

Chaque plugin autorisé a un fichier JSON nommé `<plugin_id>.json`. Le schéma est défini dans
[`src/wedr_plugin/manifest.rs`](src/wedr_plugin/manifest.rs) et **doit rester identique octet
pour octet** à `WazabiEDR_Agent::plugin::manifest::PluginManifest`. (La structure est
**volontairement dupliquée** des deux côtés plutôt que partagée via une crate commune : cela
évite que l'outil tire transitivement les types d'événements kernel et les fonctionnalités
`windows-sys` de l'agent. Un commentaire dans chaque fichier pointe vers l'autre.)

```jsonc
{
  "plugin_id":       "8f3c1d8e-5a8b-4ad0-94d2-cab9b1d0e2a0", // UUID v4 = nom de fichier
  "name":            "Acme Telemetry",                        // libellé humain
  "vendor":          "Acme Corp",
  "expected_path":   "C:\\Program Files\\Acme\\acme-plugin.exe", // chemin absolu attendu
  "expected_sha256": "f4b9...64hex",                          // empreinte du binaire
  "expected_signer": "CN=Acme Corp, O=Acme, C=FR",            // DN Authenticode (optionnel)
  "revoked":         false,                                   // true = l'agent refuse ce plugin
  "enrolled_at":     "2026-05-09T20:50:04Z",                  // informatif
  "auto_launch":     false                                    // true = supervisé/relancé par l'agent
}
```

| Champ | Requis | Signification |
|---|---|---|
| `plugin_id` | oui | UUID v4. **Doit égaler le nom de fichier** (sans `.json`). |
| `name`, `vendor` | oui | Texte libre. |
| `expected_path` | oui | Chemin **absolu** où doit se trouver le binaire connecté. Comparé sans tenir compte de la casse. Sans préfixe `\\?\`. |
| `expected_sha256` | au moins un des deux | SHA-256 (hex minuscule) du binaire. |
| `expected_signer` | au moins un des deux | DN du sujet Authenticode. En v1 : active seulement l'exigence « doit être signé », le sujet n'est pas encore comparé. |
| `revoked` | non | `true` ⇒ l'agent rejette ce plugin (motif `revoked`). |
| `enrolled_at` | non | Horodatage ISO-8601 posé par `enroll`. **Purement informatif** — l'agent ne le lit jamais. |
| `auto_launch` | non | `true` ⇒ le superviseur de l'agent lance ce plugin au démarrage et le relance après crash (backoff exponentiel). Défaut `false`. |

**Invariant clé** : `expected_sha256` et `expected_signer` sont tous deux optionnels, mais **au
moins un doit être présent**. Un manifest sans aucun contrôle d'intégrité est rejeté au
chargement par l'agent (il n'y aurait aucun moyen de vérifier que le binaire connecté n'a pas
été remplacé) — d'où le garde-fou de `enroll` qui exige `--signer` *ou* `--allow-unsigned` (§4).

---

## 3. Anatomie du CLI

[`src/wedr_plugin/main.rs`](src/wedr_plugin/main.rs) est un *dispatcher* simple : `main` lit le
premier argument (la sous-commande) et appelle le `cmd_*` correspondant. Chaque sous-commande est
une fonction autonome, sans état partagé au-delà de `default_dir()`.

| Sous-commande | Fonction | Effet |
|---|---|---|
| `enroll <bin> --name --vendor [--signer\|--allow-unsigned] [--auto-launch] [--out-dir]` | `cmd_enroll` | Crée un nouveau manifest |
| `update <id> [<bin>] [--auto-launch\|--no-auto-launch] [--dir]` | `cmd_update` | Re-hash le binaire / change le chemin / bascule auto_launch |
| `list [--dir]` | `cmd_list` | Tableau de tous les manifests |
| `show <id> [--dir]` | `cmd_show` | Affiche un manifest (JSON) |
| `doctor [--dir]` | `cmd_doctor` | Détecte les dérives ; code de sortie ≠ 0 si un plugin est malsain |
| `path [--dir]` | `cmd_path` | Imprime le dossier de manifests |
| `revoke` / `unrevoke <id>` | `cmd_set_revoked` | Bascule le drapeau `revoked` |
| `auto-launch` / `no-auto-launch <id>` | `cmd_set_auto_launch` | Bascule le drapeau `auto_launch` |
| `remove <id>` | `cmd_remove` | Supprime le fichier manifest (destructif, pas d'annulation) |

**Conventions** : le dossier par défaut est `%ProgramData%\WazabiEDR\plugins` ; la plupart des
commandes acceptent `--dir <chemin>` pour le surcharger (`enroll` utilise `--out-dir` pour la
même chose, réservé aux tests sans toucher à `%ProgramData%`). Les **codes de sortie** sont
`0` = succès, `1` = échec opérationnel (I/O, validation), `2` = erreur d'arguments.

---

## 4. `enroll`, étape par étape

`cmd_enroll` ([`main.rs`](src/wedr_plugin/main.rs)) est la commande centrale. Son déroulé :

1. **Parsing + garde-fou d'intégrité.** Si ni `--signer` ni `--allow-unsigned` n'est passé, on
   **refuse** : enrôler un plugin sans aucun contrôle d'intégrité laisserait n'importe quel
   binaire au bon chemin l'usurper. `--allow-unsigned` est une reconnaissance explicite (« je
   sais que je n'épingle que par SHA-256, OK pour le dev ») ; `--signer "<DN>"` est le chemin
   prod (et le SHA est **toujours** enregistré en plus).
2. **Résolution du chemin.** `std::fs::canonicalize` vérifie que le fichier existe et renvoie un
   chemin absolu — mais, sous Windows, **toujours** préfixé `\\?\` (forme « extended-length »).
   `strip_extended_prefix` retire ce préfixe, car l'agent compare au runtime via
   `QueryFullProcessImageNameW`, qui **ne** renvoie **jamais** ce préfixe. Les deux chaînes
   doivent être égales. On **refuse** de stripper un `\\?\UNC\…` (cela transformerait un chemin
   réseau en chemin d'apparence locale — un piège).
3. **Hash SHA-256** du binaire (`sha256_file_hex`, §5).
4. **Génération du `plugin_id`** (UUID v4, §5).
5. **Horodatage** ISO-8601 (`GetSystemTime`).
6. **Construction du `PluginManifest`** : `expected_sha256` est **toujours** rempli (le hash a
   été calculé de toute façon — pin plus serré qu'on peut choisir d'imposer plus tard, et utile
   à `doctor` dans les deux modes) ; `revoked: false` par défaut.
7. **Résolution du dossier de sortie** (`--out-dir` ou `default_dir()`), `create_dir_all`
   (idempotent).
8. **Anti-collision** : si `<plugin_id>.json` existe déjà, on **refuse d'écraser** (une collision
   d'UUID v4 est astronomiquement improbable, mais on ne risque pas de clobber un manifest
   existant).
9. **Écriture** du JSON *pretty* (`to_vec_pretty` + `fs::write`).
10. **Résumé** sur stdout, avec le `plugin_id` imprimé **deux fois** — une fois dans le résumé,
    une fois isolé en bas pour le copier-coller (et le grep des scripts).

Le `plugin_id` est **public** (il finit dans le nom de fichier, le code source du plugin, et
chaque événement émis). Ce n'est pas un secret : ce qui empêche l'usurpation est la vérification
d'identité au handshake, côté agent.

---

## 5. Cryptographie sans dépendance (SHA-256 & UUID)

Tout passe par **BCrypt CNG** (*Cryptography API: Next Generation* : l'API cryptographique de
Windows), sans crate tierce :

- **SHA-256** ([`src/wedr_plugin/sha256.rs`](src/wedr_plugin/sha256.rs)) : `sha256_file_hex`
  ouvre le fichier avec `CreateFileW`, instancie un fournisseur d'algorithme SHA-256, hashe par
  **morceaux de 64 Kio** et renvoie l'hexadécimal minuscule. C'est **exactement la même
  routine** que celle de l'agent (`WazabiEDR_Agent/src/plugin/identity.rs`) — même API, même
  taille de morceau, même formatage — de sorte que le hash d'enrôlement et le hash de runtime
  **coïncident** garantissement pour un binaire inchangé.
- **UUID v4** ([`src/wedr_plugin/uuid.rs`](src/wedr_plugin/uuid.rs)) : `v4_string` tire 16 octets
  d'entropie système via `BCryptGenRandom`, pose les bits de version (`0x40`) et de variante
  (`0x80`) selon la RFC 4122 §4.4, et formate en `8-4-4-4-12`. Un vrai UUID v4 conforme, sans la
  crate `uuid`.

---

## 6. Les autres sous-commandes

Mécaniquement simples — toutes lisent le(s) manifest(s), agissent, réécrivent :

- **`update`** : relit le manifest, recalcule le SHA-256 (et, si un nouveau `<bin>` est fourni,
  réécrit `expected_path`), réécrit. Sort sur « manifest already up-to-date » si le SHA n'a pas
  bougé. `--auto-launch`/`--no-auto-launch` basculent le drapeau sans rebuild. **Le `plugin_id`
  ne change jamais** — le code du plugin continue de fonctionner sans modification.
- **`revoke`/`unrevoke`** : bascule `revoked`, réécrit. L'agent prend en compte en ~5 s
  (hot-reload). **Les sessions en cours ne sont pas tuées** — seules les nouvelles connexions
  sont affectées.
- **`auto-launch`/`no-auto-launch`** : bascule `auto_launch`. Le superviseur de l'agent ne lit ce
  drapeau **qu'au démarrage** — il faut redémarrer l'agent pour qu'il prenne effet.
- **`doctor`** : pour chaque manifest, vérifie (dans l'ordre) la validité du schéma (au moins un
  contrôle d'intégrité), l'existence du binaire à `expected_path`, la correspondance du SHA-256,
  et le drapeau `revoked`. Préfixes `✓` / `⚠` / `✗`. **Code de sortie ≠ 0** si un plugin est
  malsain → idéal en tâche planifiée.
- **`list`/`show`/`path`** : lecture seule (tableau / JSON / chemin du dossier).
- **`remove`** : `fs::remove_file`. **Destructif, sans annulation** — préférer `revoke` pour une
  désactivation temporaire.

`read_manifests` ([`main.rs`](src/wedr_plugin/main.rs)) est tolérant : un fichier illisible ou
non conforme est **signalé sur stderr et ignoré**, sans bloquer l'opération.

---

## 7. Ce qui se passe côté agent (hot-reload)

`wedr-plugin` n'a aucun lien direct avec l'agent : il se contente d'écrire des fichiers. C'est
l'**agent** qui surveille le dossier. Toutes les ~5 secondes, un thread de l'ag
recharge le dossier de manifests (il compare une *empreinte de répertoire* — un FNV-1a sur les
tuples `(nom, mtime, taille)` — pour détecter un changement sans relire le contenu), puis
échange atomiquement son magasin de manifests en mémoire. Donc **aucun redémarrage de l'agent
n'est nécessaire** après un `enroll`/`revoke`/`remove` : le changement est pris en compte au
prochain tick.

Conséquences pour l'opérateur :

| Opération | Vu par | Pas vu par |
|---|---|---|
| `enroll` (nouveau fichier) | connexions acceptées dès maintenant | — |
| `update` (SHA/chemin changé) | prochaine connexion | session en cours (continue) |
| `revoke` | prochaine connexion rejetée | session en cours (continue) |
| `remove` (fichier supprimé) | prochaine connexion rejetée (`unknown_plugin_id`) | session en cours (continue) |

Le détail du magasin en mémoire, du verrou `Arc<RwLock<Arc<…>>>` et de la vérification
d'identité à trois couches est documenté côté **agent** (`WazabiEDR_Agent` → `ARCHITECTURE.md`,
§ serveur de plugins).

---

## 8. Par où commencer

1. [`src/wedr_plugin/main.rs`](src/wedr_plugin/main.rs) — le dispatcher et `cmd_enroll`.
2. [`src/wedr_plugin/manifest.rs`](src/wedr_plugin/manifest.rs) — le schéma (le contrat avec
   l'agent).
3. [`src/wedr_plugin/sha256.rs`](src/wedr_plugin/sha256.rs) &
   [`uuid.rs`](src/wedr_plugin/uuid.rs) — la crypto sans dépendance.

Documentation associée :

- 🧑‍💻 **Guide opérateur** (chaque commande avec exemples) : [`doc/usage/managing-plugins.md`](doc/usage/managing-plugins.md).
- 📑 **Référence du CLI** (chaque flag) : [`doc/reference/cli-reference.md`](doc/reference/cli-reference.md).
- Côté agent : `ARCHITECTURE.md` du dépôt [`WazabiEDR_Agent`](../WazabiEDR_Agent/).
- Pour écrire un plugin : dépôt [`WazabiEDR_PluginSDK`](../WazabiEDR_PluginSDK/).
