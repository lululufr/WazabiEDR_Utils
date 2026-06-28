//! `wedr-plugin` — administrator-side tooling for the WazabiEDR plugin
//! protocol.
//!
//! Subcommands:
//!
//! ```text
//!   wedr-plugin enroll <binary> --name <NAME> --vendor <VENDOR>
//!                              [--signer "CN=..."] [--allow-unsigned]
//!                              [--out-dir <DIR>]
//!
//!   wedr-plugin list           [--dir <DIR>]
//!   wedr-plugin revoke <PLUGIN_ID>     [--dir <DIR>]
//!   wedr-plugin unrevoke <PLUGIN_ID>   [--dir <DIR>]
//!   wedr-plugin remove <PLUGIN_ID>     [--dir <DIR>]
//!   wedr-plugin show <PLUGIN_ID>       [--dir <DIR>]
//! ```
//!
//! Default `--dir` is `%ProgramData%\WazabiEDR\plugins\`. Writing to
//! that directory requires Administrator privileges (it is ACL'd that
//! way at install time on production endpoints).
//!
//! # Why not bundle this into the agent?
//!
//! Enrolment is a one-shot administrative action — it should not run
//! inside the long-lived agent process. Keeping it as a separate exe
//! also makes it composable (CI scripts, MSI custom actions, …).

mod manifest;
mod sha256;
mod uuid;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::manifest::PluginManifest;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = match args.first().map(String::as_str) {
        Some(c) => c,
        None => {
            print_usage();
            return ExitCode::from(2);
        }
    };

    let result = match cmd {
        "enroll" => cmd_enroll(&args[1..]),
        "update" => cmd_update(&args[1..]),
        "list" => cmd_list(&args[1..]),
        "show" => cmd_show(&args[1..]),
        "doctor" => cmd_doctor(&args[1..]),
        "path" => cmd_path(&args[1..]),
        "revoke" => cmd_set_revoked(&args[1..], true),
        "unrevoke" => cmd_set_revoked(&args[1..], false),
        "auto-launch" => cmd_set_auto_launch(&args[1..], true),
        "no-auto-launch" => cmd_set_auto_launch(&args[1..], false),
        "remove" => cmd_remove(&args[1..]),
        "-h" | "--help" | "help" => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        other => Err(format!("unknown subcommand: {other} (try --help)")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn print_usage() {
    eprintln!(
        "wedr-plugin — WazabiEDR plugin enrolment\n\
         \n\
         USAGE:\n  \
           wedr-plugin enroll <BINARY> --name <NAME> --vendor <VENDOR> \\\n  \
                              [--signer \"CN=...\"] [--allow-unsigned] \\\n  \
                              [--auto-launch] [--out-dir <DIR>]\n  \
           wedr-plugin update <PLUGIN_ID> [<BINARY>] \\\n  \
                              [--auto-launch | --no-auto-launch] [--dir <DIR>]\n  \
           wedr-plugin list                               [--dir <DIR>]\n  \
           wedr-plugin show <PLUGIN_ID>                   [--dir <DIR>]\n  \
           wedr-plugin doctor                             [--dir <DIR>]\n  \
           wedr-plugin path                               [--dir <DIR>]\n  \
           wedr-plugin revoke <PLUGIN_ID>                 [--dir <DIR>]\n  \
           wedr-plugin unrevoke <PLUGIN_ID>               [--dir <DIR>]\n  \
           wedr-plugin auto-launch <PLUGIN_ID>            [--dir <DIR>]\n  \
           wedr-plugin no-auto-launch <PLUGIN_ID>         [--dir <DIR>]\n  \
           wedr-plugin remove <PLUGIN_ID>                 [--dir <DIR>]\n  \
         \n\
         The default manifest directory is %ProgramData%\\WazabiEDR\\plugins.\n\
         The agent hot-reloads this directory every 5 s — no agent restart\n\
         is needed after enrol / revoke / remove.\n\
         Run as Administrator if writing to the default location.\n\
         \n\
         enroll OPTIONS:\n  \
           --name <NAME>          Human-readable plugin name (required)\n  \
           --vendor <VENDOR>      Vendor / organisation (required)\n  \
           --signer \"<DN>\"        Authenticode subject DN; when set, the\n  \
                                  agent requires the binary to be signed.\n  \
                                  Example: \"CN=Acme Corp, O=Acme, C=FR\"\n  \
           --allow-unsigned       Skip signer requirement; integrity is\n  \
                                  enforced via SHA-256 only. Use for dev.\n  \
           --auto-launch          Have the agent's supervisor spawn this\n  \
                                  plugin at startup and restart it on\n  \
                                  crash (exponential backoff, cap 60 s).\n  \
                                  Default: off — operators opt in.\n  \
           --out-dir <DIR>        Override the manifest output directory.\n\
         \n\
         update <PLUGIN_ID> [<BINARY>]:\n  \
           Re-hash the binary and refresh expected_sha256 in the manifest.\n  \
           Without <BINARY>, re-hashes whatever is at the manifest's\n  \
           expected_path. With <BINARY>, also updates expected_path.\n  \
           Use after rebuilding a plugin so an SHA-pinned manifest stops\n  \
           rejecting the new build.\n  \
           --auto-launch / --no-auto-launch toggle the supervisor flag\n  \
           without rebuilding the binary.\n\
         \n\
         auto-launch / no-auto-launch <PLUGIN_ID>:\n  \
           Toggle the supervisor's auto_launch flag on a single plugin.\n  \
           When auto_launch is on, the agent spawns this plugin at\n  \
           startup and restarts it on crash with exponential backoff.\n  \
           Note: the supervisor reads this at agent startup only —\n  \
           restart the agent for the change to take effect.\n\
         \n\
         doctor:\n  \
           Walks every enrolled manifest and reports drift:\n  \
             - missing binary at expected_path\n  \
             - SHA-256 of the binary differs from expected_sha256\n  \
             - manifest fails schema validation\n  \
           Returns non-zero exit code if any plugin is unhealthy."
    );
}

// =====================================================================
// enroll
// =====================================================================

struct EnrollArgs {
    binary: PathBuf,
    name: String,
    vendor: String,
    signer: Option<String>,
    allow_unsigned: bool,
    out_dir: Option<PathBuf>,
    auto_launch: bool,
    /// `--env KEY=VALUE` répétable. Vide par défaut. Sera sérialisé tel
    /// quel dans `PluginManifest.env` et appliqué par le supervisor agent
    /// au moment du spawn.
    env: std::collections::HashMap<String, String>,
}

fn parse_enroll(args: &[String]) -> Result<EnrollArgs, String> {
    let mut binary: Option<PathBuf> = None;
    let mut name: Option<String> = None;
    let mut vendor: Option<String> = None;
    let mut signer: Option<String> = None;
    let mut allow_unsigned = false;
    let mut out_dir: Option<PathBuf> = None;
    let mut auto_launch = false;
    let mut env: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => {
                name = Some(next_value(args, &mut i, "--name")?);
            }
            "--vendor" => {
                vendor = Some(next_value(args, &mut i, "--vendor")?);
            }
            "--signer" => {
                signer = Some(next_value(args, &mut i, "--signer")?);
            }
            "--allow-unsigned" => {
                allow_unsigned = true;
                i += 1;
            }
            "--out-dir" => {
                out_dir = Some(PathBuf::from(next_value(args, &mut i, "--out-dir")?));
            }
            "--auto-launch" => {
                auto_launch = true;
                i += 1;
            }
            "--env" => {
                let kv = next_value(args, &mut i, "--env")?;
                // KEY=VALUE — VALUE peut contenir des '=' (URL, JSON), donc
                // on splitn(2) plutôt que split.
                let (k, v) = kv.split_once('=').ok_or_else(|| {
                    format!("--env expects KEY=VALUE, got: {kv}")
                })?;
                if k.is_empty() {
                    return Err(format!("--env: empty KEY in {kv}"));
                }
                env.insert(k.to_string(), v.to_string());
            }
            other if !other.starts_with("--") && binary.is_none() => {
                binary = Some(PathBuf::from(other));
                i += 1;
            }
            other => return Err(format!("unexpected argument: {other}")),
        }
    }

    Ok(EnrollArgs {
        binary: binary.ok_or_else(|| "missing <BINARY> path".to_string())?,
        name: name.ok_or_else(|| "missing --name".to_string())?,
        vendor: vendor.ok_or_else(|| "missing --vendor".to_string())?,
        signer,
        allow_unsigned,
        out_dir,
        auto_launch,
        env,
    })
}

fn cmd_enroll(args: &[String]) -> Result<(), String> {
    let opts = parse_enroll(args)?;

    if opts.signer.is_none() && !opts.allow_unsigned {
        return Err(
            "you must pass either --signer \"<DN>\" or --allow-unsigned. \
             Refusing to enrol a plugin with no integrity guarantee."
                .into(),
        );
    }

    // Resolve the binary path to its absolute, canonical form. The agent
    // compares the manifest's expected_path against the connecting
    // process's QueryFullProcessImageNameW result, which is always
    // absolute — relative paths in the manifest would never match.
    let abs = std::fs::canonicalize(&opts.binary)
        .map_err(|e| format!("cannot resolve {:?}: {}", opts.binary, e))?;
    // canonicalize on Windows returns a `\\?\` "extended-length" prefix
    // — strip it so the manifest matches what QueryFullProcessImageNameW
    // returns (which does NOT include the prefix).
    let abs = strip_extended_prefix(&abs);

    let sha256 = sha256::sha256_file_hex(&abs)
        .map_err(|e| format!("cannot hash {:?}: {}", abs, e))?;

    let plugin_id = uuid::v4_string()
        .map_err(|e| format!("cannot generate plugin_id: {}", e))?;

    let now = iso8601_utc_now();

    let manifest = PluginManifest {
        plugin_id: plugin_id.clone(),
        name: opts.name,
        vendor: opts.vendor,
        expected_path: abs.to_string_lossy().to_string(),
        expected_sha256: Some(sha256),
        expected_signer: opts.signer.clone(),
        revoked: false,
        enrolled_at: Some(now),
        auto_launch: opts.auto_launch,
        env: opts.env,
    };

    let dir = opts.out_dir.unwrap_or_else(default_dir);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("cannot create {:?}: {}", dir, e))?;

    let out = dir.join(format!("{}.json", plugin_id));
    if out.exists() {
        // plugin_id collision is astronomically unlikely (128 bits),
        // but if it ever happens we'd rather refuse than overwrite.
        return Err(format!(
            "manifest already exists at {:?} — collision? refusing to overwrite",
            out
        ));
    }

    let json = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| format!("serialise manifest: {}", e))?;
    std::fs::write(&out, &json)
        .map_err(|e| format!("write {:?}: {}", out, e))?;

    println!("enrolled plugin");
    println!("  plugin_id     : {}", plugin_id);
    println!("  name          : {}", manifest.name);
    println!("  vendor        : {}", manifest.vendor);
    println!("  expected_path : {}", manifest.expected_path);
    println!("  auto_launch   : {}", manifest.auto_launch);
    println!("  manifest      : {}", out.display());
    if opts.allow_unsigned {
        println!(
            "  WARNING: --allow-unsigned was used; integrity is enforced \
             via SHA-256 only. The manifest will need to be re-issued any \
             time the binary is updated."
        );
    }
    println!();
    println!("Hand the plugin_id to the plugin author so they can hardcode it");
    println!("in their HELLO frame:");
    println!();
    println!("    {}", plugin_id);

    Ok(())
}

// =====================================================================
// update — re-hash a manifest after the plugin binary was rebuilt
// =====================================================================

fn cmd_update(args: &[String]) -> Result<(), String> {
    // `wedr-plugin update <PLUGIN_ID>            [--dir <DIR>] [--auto-launch | --no-auto-launch]`
    // `wedr-plugin update <PLUGIN_ID> <BINARY>   [--dir <DIR>] [--auto-launch | --no-auto-launch]`
    //
    // Without <BINARY> and without --(no-)auto-launch, this re-hashes
    // whatever is at the manifest's expected_path. Any combination of
    // <BINARY> + auto-launch toggle is allowed; either one alone counts
    // as "something changed" and triggers the write.
    let mut id: Option<String> = None;
    let mut binary: Option<PathBuf> = None;
    let mut dir: Option<PathBuf> = None;
    let mut new_auto_launch: Option<bool> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" => dir = Some(PathBuf::from(next_value(args, &mut i, "--dir")?)),
            "--auto-launch" => {
                new_auto_launch = Some(true);
                i += 1;
            }
            "--no-auto-launch" => {
                new_auto_launch = Some(false);
                i += 1;
            }
            other if !other.starts_with("--") && id.is_none() => {
                id = Some(other.to_string());
                i += 1;
            }
            other if !other.starts_with("--") && binary.is_none() => {
                binary = Some(PathBuf::from(other));
                i += 1;
            }
            other => return Err(format!("unexpected argument: {other}")),
        }
    }

    let id = id.ok_or_else(|| "missing PLUGIN_ID".to_string())?;
    let dir = dir.unwrap_or_else(default_dir);
    let path = dir.join(format!("{}.json", id));

    let bytes = std::fs::read(&path).map_err(|e| format!("read {:?}: {}", path, e))?;
    let mut m: PluginManifest =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse {:?}: {}", path, e))?;

    // Decide which binary to re-hash:
    //   - explicit: the path the user passed
    //   - default : the manifest's existing expected_path
    let target = match binary {
        Some(p) => {
            let abs = std::fs::canonicalize(&p)
                .map_err(|e| format!("cannot resolve {:?}: {}", p, e))?;
            let abs = strip_extended_prefix(&abs);
            // Updating expected_path moves the trust anchor — make
            // sure the operator notices that this changed.
            if abs.to_string_lossy() != m.expected_path {
                println!(
                    "  expected_path : {} → {}",
                    m.expected_path,
                    abs.display()
                );
                m.expected_path = abs.to_string_lossy().to_string();
            }
            abs
        }
        None => PathBuf::from(&m.expected_path),
    };

    let new_sha = sha256::sha256_file_hex(&target)
        .map_err(|e| format!("cannot hash {:?}: {}", target, e))?;
    let prev_sha = m.expected_sha256.clone().unwrap_or_default();
    let sha_changed = prev_sha != new_sha;

    // Auto-launch toggle: only count as "changed" if the new value
    // differs from what's already on disk.
    let prev_auto = m.auto_launch;
    let auto_changed = match new_auto_launch {
        Some(v) => v != prev_auto,
        None => false,
    };

    if !sha_changed && !auto_changed {
        println!("manifest already up-to-date for {}", id);
        return Ok(());
    }

    if sha_changed {
        m.expected_sha256 = Some(new_sha.clone());
    }
    if let Some(v) = new_auto_launch {
        m.auto_launch = v;
    }

    let json = serde_json::to_vec_pretty(&m).map_err(|e| format!("serialise: {}", e))?;
    std::fs::write(&path, &json).map_err(|e| format!("write {:?}: {}", path, e))?;

    println!("updated manifest for {}", id);
    if sha_changed {
        println!("  expected_sha256 : {} → {}", prev_sha, new_sha);
    }
    if auto_changed {
        println!("  auto_launch     : {} → {}", prev_auto, m.auto_launch);
    }
    Ok(())
}

// =====================================================================
// doctor — drift detection over the enrolled set
// =====================================================================

fn cmd_doctor(args: &[String]) -> Result<(), String> {
    let dir = parse_dir_only(args)?;
    let entries = read_manifests(&dir)?;

    if entries.is_empty() {
        println!("no plugins enrolled in {}", dir.display());
        return Ok(());
    }

    // Counters so we can return non-zero when any plugin is unhealthy
    // — useful for a CI / scheduled-task drift check.
    let mut warnings = 0;
    let mut errors = 0;

    println!(
        "checking {} plugin(s) in {}",
        entries.len(),
        dir.display()
    );

    for m in &entries {
        let id_short = if m.plugin_id.len() > 8 {
            &m.plugin_id[..8]
        } else {
            &m.plugin_id
        };

        // Manifest schema sanity (mirrors the agent's load-time check).
        if m.expected_sha256.is_none() && m.expected_signer.is_none() {
            println!(
                "  ✗ {}… {} — manifest declares no integrity check (would be rejected by agent)",
                id_short, m.name
            );
            errors += 1;
            continue;
        }

        let bin_path = PathBuf::from(&m.expected_path);
        if !bin_path.exists() {
            println!(
                "  ✗ {}… {} — binary not found: {}",
                id_short, m.name, m.expected_path
            );
            errors += 1;
            continue;
        }

        if let Some(expected) = m.expected_sha256.as_deref() {
            match sha256::sha256_file_hex(&bin_path) {
                Ok(actual) if actual.eq_ignore_ascii_case(expected) => {
                    if m.revoked {
                        println!(
                            "  ⚠ {}… {} — REVOKED (would be rejected by agent)",
                            id_short, m.name
                        );
                        warnings += 1;
                    } else {
                        println!("  ✓ {}… {}", id_short, m.name);
                    }
                }
                Ok(actual) => {
                    println!(
                        "  ✗ {}… {} — SHA-256 drifted",
                        id_short, m.name
                    );
                    println!("       expected : {}", expected);
                    println!("       actual   : {}", actual);
                    println!(
                        "       fix      : wedr-plugin update {}",
                        m.plugin_id
                    );
                    errors += 1;
                }
                Err(e) => {
                    println!(
                        "  ✗ {}… {} — cannot hash binary: {}",
                        id_short, m.name, e
                    );
                    errors += 1;
                }
            }
        } else if m.revoked {
            println!(
                "  ⚠ {}… {} — REVOKED (would be rejected by agent)",
                id_short, m.name
            );
            warnings += 1;
        } else {
            // Signer-only manifest: we can't verify Authenticode here
            // without re-implementing WinVerifyTrust, so we just note
            // that the binary exists. The agent will check at runtime.
            println!(
                "  ✓ {}… {} (signer-only, runtime-verified)",
                id_short, m.name
            );
        }
    }

    println!();
    println!("summary: {} ok, {} warning(s), {} error(s)",
        entries.len() - warnings - errors,
        warnings,
        errors,
    );

    if errors > 0 {
        Err(format!("{} plugin(s) unhealthy", errors))
    } else {
        Ok(())
    }
}

// =====================================================================
// path — print the manifest directory (handy for scripting)
// =====================================================================

fn cmd_path(args: &[String]) -> Result<(), String> {
    let dir = parse_dir_only(args)?;
    println!("{}", dir.display());
    Ok(())
}

// =====================================================================
// list / show / revoke / remove
// =====================================================================

fn cmd_list(args: &[String]) -> Result<(), String> {
    let dir = parse_dir_only(args)?;
    let mut entries = read_manifests(&dir)?;
    entries.sort_by(|a, b| a.plugin_id.cmp(&b.plugin_id));

    if entries.is_empty() {
        println!("no plugins enrolled in {}", dir.display());
        return Ok(());
    }

    println!(
        "{:<38} {:<30} {:<8} {:<10} {}",
        "plugin_id", "name", "revoked", "auto-launch", "vendor"
    );
    for m in entries {
        println!(
            "{:<38} {:<30} {:<8} {:<10} {}",
            m.plugin_id,
            truncate(&m.name, 30),
            if m.revoked { "yes" } else { "no" },
            if m.auto_launch { "yes" } else { "no" },
            m.vendor
        );
    }
    Ok(())
}

fn cmd_show(args: &[String]) -> Result<(), String> {
    let (id, dir) = parse_id_and_dir(args)?;
    let path = dir.join(format!("{}.json", id));
    let bytes = std::fs::read(&path)
        .map_err(|e| format!("read {:?}: {}", path, e))?;
    // Re-serialise pretty so the on-disk file (which may be terse) is
    // displayed in a stable, human-friendly form.
    let m: PluginManifest = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse {:?}: {}", path, e))?;
    let pretty = serde_json::to_string_pretty(&m)
        .map_err(|e| format!("re-serialise: {}", e))?;
    println!("{}", pretty);
    Ok(())
}

fn cmd_set_revoked(args: &[String], revoke: bool) -> Result<(), String> {
    let (id, dir) = parse_id_and_dir(args)?;
    let path = dir.join(format!("{}.json", id));
    let bytes = std::fs::read(&path)
        .map_err(|e| format!("read {:?}: {}", path, e))?;
    let mut m: PluginManifest = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse {:?}: {}", path, e))?;
    m.revoked = revoke;
    let json = serde_json::to_vec_pretty(&m)
        .map_err(|e| format!("serialise: {}", e))?;
    std::fs::write(&path, &json)
        .map_err(|e| format!("write {:?}: {}", path, e))?;
    println!(
        "{} {}",
        if revoke { "revoked" } else { "unrevoked" },
        id
    );
    println!("agent will pick this up automatically within ~5 s (hot-reload)");
    Ok(())
}

fn cmd_set_auto_launch(args: &[String], enable: bool) -> Result<(), String> {
    let (id, dir) = parse_id_and_dir(args)?;
    let path = dir.join(format!("{}.json", id));
    let bytes = std::fs::read(&path)
        .map_err(|e| format!("read {:?}: {}", path, e))?;
    let mut m: PluginManifest = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse {:?}: {}", path, e))?;

    if m.auto_launch == enable {
        // No-op: writing would just bump mtime and trigger a needless
        // hot-reload on the agent side. Be explicit so the operator
        // knows nothing changed.
        println!(
            "{} already auto_launch={}",
            id, m.auto_launch
        );
        return Ok(());
    }

    let prev = m.auto_launch;
    m.auto_launch = enable;
    let json = serde_json::to_vec_pretty(&m)
        .map_err(|e| format!("serialise: {}", e))?;
    std::fs::write(&path, &json)
        .map_err(|e| format!("write {:?}: {}", path, e))?;
    println!("auto_launch {}: {} → {}", id, prev, m.auto_launch);
    println!(
        "note: the agent's supervisor reads this at startup only; \
         restart the agent for the change to take effect."
    );
    Ok(())
}

fn cmd_remove(args: &[String]) -> Result<(), String> {
    let (id, dir) = parse_id_and_dir(args)?;
    let path = dir.join(format!("{}.json", id));
    std::fs::remove_file(&path)
        .map_err(|e| format!("remove {:?}: {}", path, e))?;
    println!("removed {}", id);
    Ok(())
}

// =====================================================================
// helpers
// =====================================================================

fn next_value(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    if *i + 1 >= args.len() {
        return Err(format!("{flag} requires a value"));
    }
    let v = args[*i + 1].clone();
    *i += 2;
    Ok(v)
}

fn parse_dir_only(args: &[String]) -> Result<PathBuf, String> {
    let mut dir: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" => dir = Some(PathBuf::from(next_value(args, &mut i, "--dir")?)),
            other => return Err(format!("unexpected argument: {other}")),
        }
    }
    Ok(dir.unwrap_or_else(default_dir))
}

fn parse_id_and_dir(args: &[String]) -> Result<(String, PathBuf), String> {
    let mut id: Option<String> = None;
    let mut dir: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" => dir = Some(PathBuf::from(next_value(args, &mut i, "--dir")?)),
            other if !other.starts_with("--") && id.is_none() => {
                id = Some(other.to_string());
                i += 1;
            }
            other => return Err(format!("unexpected argument: {other}")),
        }
    }
    Ok((
        id.ok_or_else(|| "missing PLUGIN_ID".to_string())?,
        dir.unwrap_or_else(default_dir),
    ))
}

fn read_manifests(dir: &Path) -> Result<Vec<PluginManifest>, String> {
    let mut out = Vec::new();
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(format!("read {:?}: {}", dir, e)),
    };
    for entry in read.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[wedr-plugin] skipping {:?}: {}", path, e);
                continue;
            }
        };
        match serde_json::from_slice::<PluginManifest>(&bytes) {
            Ok(m) => out.push(m),
            Err(e) => eprintln!("[wedr-plugin] not a valid manifest {:?}: {}", path, e),
        }
    }
    Ok(out)
}

fn default_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"));
    base.join("WazabiEDR").join("plugins")
}

/// `\\?\C:\foo` → `C:\foo`. Win32 canonicalize produces the prefixed
/// form to allow paths longer than MAX_PATH; the agent compares against
/// QueryFullProcessImageNameW results which never include the prefix.
fn strip_extended_prefix(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        // Reject a UNC path masquerading as a local one — we never
        // expect to enrol a network-mounted plugin.
        if rest.starts_with("UNC\\") {
            return p.to_path_buf();
        }
        PathBuf::from(rest)
    } else {
        p.to_path_buf()
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// `2026-05-09T14:00:00Z` from UTC. Hand-formatted so we don't pull in
/// a `chrono` dependency just for this one call.
fn iso8601_utc_now() -> String {
    use std::mem::MaybeUninit;
    use windows_sys::Win32::Foundation::SYSTEMTIME;
    unsafe extern "system" {
        fn GetSystemTime(t: *mut SYSTEMTIME);
    }

    let mut st: MaybeUninit<SYSTEMTIME> = MaybeUninit::uninit();
    unsafe { GetSystemTime(st.as_mut_ptr()) };
    let st = unsafe { st.assume_init() };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
    )
}
