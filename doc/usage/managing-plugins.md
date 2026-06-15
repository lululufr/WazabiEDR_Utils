# Gérer les plugins

> Chaque sous-commande `wedr-plugin`, avec la sortie de session. L'agent recharge à chaud le
> dossier de manifests toutes les 5 s — aucun redémarrage nécessaire après l'une de ces
> opérations.

`wedr-plugin` écrit, lit et édite les fichiers manifests sous `%ProgramData%\WazabiEDR\plugins\`.
La plupart des opérations nécessitent une élévation (Administrateur). Pour le détail interne de
ce que fait `enroll`, voir [`ARCHITECTURE.md`](../../ARCHITECTURE.md) §4.

---

## Découverte — `path` et `list`

```powershell
PS> wedr-plugin path
C:\ProgramData\WazabiEDR\plugins

PS> wedr-plugin list
plugin_id                              name                           revoked  vendor
8f3c1d8e-5a8b-4ad0-94d2-cab9b1d0e2a0   Acme Telemetry                 no       Acme Corp
b2e91234-aabb-ccdd-eeff-001122334455   Beta Logger                    yes      Beta Ltd
```

La colonne `name` est tronquée à 30 caractères. Inspection complète avec `show`.

## Inspection — `show`

```powershell
PS> wedr-plugin show 8f3c1d8e-5a8b-4ad0-94d2-cab9b1d0e2a0
{
  "plugin_id": "8f3c1d8e-5a8b-4ad0-94d2-cab9b1d0e2a0",
  "name": "Acme Telemetry",
  "vendor": "Acme Corp",
  "expected_path": "C:\\Program Files\\Acme\\acme-plugin.exe",
  "expected_sha256": "f4b9e3c8a1d52f3b...64hex",
  "expected_signer": null,
  "revoked": false,
  "enrolled_at": "2026-05-09T20:50:04Z",
  "auto_launch": false
}
```

## Enrôlement — `enroll`

### Mode dev (sans Authenticode)

Épinglage par SHA-256 seul. Utile pendant l'itération, sans certificat de signature.

```powershell
PS> wedr-plugin enroll `
        "C:\Program Files\Acme\acme-plugin.exe" `
        --name   "Acme Telemetry" `
        --vendor "Acme Corp" `
        --allow-unsigned

enrolled plugin
  plugin_id     : 8f3c1d8e-5a8b-4ad0-94d2-cab9b1d0e2a0
  name          : Acme Telemetry
  vendor        : Acme Corp
  expected_path : C:\Program Files\Acme\acme-plugin.exe
  auto_launch   : false
  manifest      : C:\ProgramData\WazabiEDR\plugins\8f3c1d8e-...json
  WARNING: --allow-unsigned was used; integrity is enforced via SHA-256 only.

Hand the plugin_id to the plugin author so they can hardcode it
in their HELLO frame:

    8f3c1d8e-5a8b-4ad0-94d2-cab9b1d0e2a0
```

### Mode production (Authenticode)

Épinglage par DN du signataire (et SHA-256 — `enroll` enregistre toujours les deux).

```powershell
PS> wedr-plugin enroll `
        "C:\Program Files\Acme\acme-plugin.exe" `
        --name   "Acme Telemetry" `
        --vendor "Acme Corp" `
        --signer "CN=Acme Corp, O=Acme, C=FR"
```

> **Limite (v1)** : l'agent exécute `WinVerifyTrust` pour valider la signature, mais ne compare
> **pas encore** le DN du sujet embarqué à `expected_signer`. La comparaison du sujet est prévue.

### Plugin auto-lancé

Ajouter `--auto-launch` pour que le superviseur de l'agent lance le plugin au démarrage et le
relance après crash (backoff exponentiel). À défaut, l'opérateur lance le plugin lui-même.

---

## Maintenance — `update`

Quand le binaire est recompilé, un manifest épinglé par SHA cesse de correspondre et l'agent
rejette avec `hash_mismatch`. On rafraîchit :

```powershell
PS> wedr-plugin update 8f3c1d8e-5a8b-4ad0-94d2-cab9b1d0e2a0
updated manifest for 8f3c1d8e-5a8b-4ad0-94d2-cab9b1d0e2a0
  expected_sha256 : f4b9e3c8a1d52f3b... → 7c879424691ef166...
```

Le `plugin_id` **ne change pas** — le code source du plugin continue de fonctionner. Si le
binaire a été **déplacé**, passer le nouveau chemin : `wedr-plugin update <id> "<nouveau-chemin>"`.

---

## Audit santé — `doctor`

```powershell
PS> wedr-plugin doctor
checking 3 plugin(s) in C:\ProgramData\WazabiEDR\plugins
  ✓ 8f3c1d8e… Acme Telemetry
  ✗ b2e91234… Beta Logger — SHA-256 drifted
       expected : 1234abcd...
       actual   : f4b9e3c8...
       fix      : wedr-plugin update b2e91234-aabb-ccdd-eeff-001122334455
  ⚠ c1d2e3f4… Old Tool — REVOKED (would be rejected by agent)

summary: 1 ok, 1 warning(s), 1 error(s)
error: 1 plugin(s) unhealthy
```

Ce qu'il attrape : binaire introuvable (`✗`), SHA-256 dérivé après rebuild (`✗`), aucun contrôle
d'intégrité déclaré (`✗`, manifest invalide), `revoked` (`⚠`). **Code de sortie ≠ 0** si un
plugin est malsain → à lancer en tâche planifiée quotidienne : un manifest dérivé ne fait pas
tomber l'agent, il fait juste échouer ce plugin ; `doctor` le détecte avant que le dashboard ne
devienne silencieux.

---

## Cycle de vie — `revoke`, `unrevoke`, `remove`

```powershell
# Désactiver temporairement (pris en compte en ~5 s) :
PS> wedr-plugin revoke 8f3c1d8e-5a8b-4ad0-94d2-cab9b1d0e2a0
# Réactiver :
PS> wedr-plugin unrevoke 8f3c1d8e-5a8b-4ad0-94d2-cab9b1d0e2a0
# Supprimer définitivement (destructif) :
PS> wedr-plugin remove 8f3c1d8e-5a8b-4ad0-94d2-cab9b1d0e2a0
```

> **Les sessions en cours continuent.** Révoquer ne tue pas une session déjà validée — le worker
> détient son propre instantané du manifest au moment du handshake. Seules les nouvelles
> connexions sont rejetées. Pour tuer une session en cours, terminer le processus du plugin.
> `remove` est destructif et sans annulation : préférer `revoke` si vous pourriez vouloir le
> plugin de nouveau.

---

## Un workflow type

```powershell
# 1. Enrôler.
PS> wedr-plugin enroll "C:\Program Files\Acme\acme-plugin.exe" `
        --name "Acme Telemetry" --vendor "Acme Corp" --allow-unsigned
#    → 8f3c1d8e-5a8b-4ad0-94d2-cab9b1d0e2a0
# 2. Confirmer.
PS> wedr-plugin list
# 3. Donner le plugin_id au dev (à embarquer comme PLUGIN_ID) et lancer.
#    Les events doivent arriver dans le stdout de l'agent en quelques secondes.
# Plus tard, nouveau build :
PS> wedr-plugin update 8f3c1d8e-...
# Vérif de dérive régulière (tâche planifiée) :
PS> wedr-plugin doctor
# Mettre en sourdine immédiate :
PS> wedr-plugin revoke 8f3c1d8e-...
# Décommissionner :
PS> wedr-plugin remove 8f3c1d8e-...
```

---

## Voir aussi

- Internes & schéma du manifest : [`ARCHITECTURE.md`](../../ARCHITECTURE.md)
- Tous les flags : [`cli-reference.md`](../reference/cli-reference.md)
- Écrire un plugin : dépôt [`WazabiEDR_PluginSDK`](../../../WazabiEDR_PluginSDK/)
