//! `wedr-waza-check` — headless `.waza` rule checker.
//!
//! Conçu pour être appelé en subprocess depuis le serveur WazabiEDR
//! (FastAPI / Python) qui n'a pas de parser Rust et ne veut pas en
//! dupliquer un. Toutes les sorties sont du JSON sur stdout ; les
//! diagnostics inattendus vont sur stderr. Le code de sortie reflète
//! la sémantique métier :
//!
//! * `0` — opération réussie (la règle parse, l'évènement matche, …)
//! * `1` — opération métier négative (règle invalide, pas de match)
//! * `2` — erreur d'invocation (arguments manquants, fichier illisible)
//!
//! Sous-commandes :
//!
//! ```text
//! wedr-waza-check validate [<path> | -]
//! wedr-waza-check simulate <rules.waza> <event.json>
//! wedr-waza-check schema
//! ```
//!
//! L'event JSON attendu pour `simulate` :
//!
//! ```json
//! { "module": "kernel_callback",
//!   "event_type": "process_create",
//!   "fields": { "pid": 4688, "image_path": "C:\\Windows\\..." } }
//! ```

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use wedr_waza_core::ast::Action;
use wedr_waza_core::engine::RuleEngine;
use wedr_waza_core::event::{FieldValue, LogEvent};
use wedr_waza_core::parser::{self, DEFAULT_WINDOW};
use wedr_waza_core::schema::builtin_kernel_schema;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let sub = args.get(1).map(String::as_str).unwrap_or("");
    match sub {
        "validate" => cmd_validate(&args[2..]),
        "simulate" => cmd_simulate(&args[2..]),
        "schema" => cmd_schema(&args[2..]),
        "" | "-h" | "--help" => {
            print_usage();
            ExitCode::from(0)
        }
        other => {
            eprintln!("unknown subcommand '{}'", other);
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    eprintln!(
        "wedr-waza-check — headless .waza rule checker\n\
         \n\
         USAGE:\n  \
           wedr-waza-check validate [<path> | -]\n  \
           wedr-waza-check simulate <rules.waza> <event.json>\n  \
           wedr-waza-check schema\n\
         \n\
         All output is JSON on stdout. Exit codes: 0 success, 1 logical \
         negative (parse error / no match), 2 invocation error."
    );
}

// =====================================================================
// validate
// =====================================================================

#[derive(Serialize)]
struct ValidateError {
    line: u32,
    message: String,
}

#[derive(Serialize)]
struct ValidateOutput {
    ok: bool,
    rules: usize,
    errors: Vec<ValidateError>,
}

fn cmd_validate(args: &[String]) -> ExitCode {
    let source_arg = args.first().map(String::as_str).unwrap_or("-");
    let source = match read_source(source_arg) {
        Ok(s) => s,
        Err(e) => return invocation_error(&e),
    };

    match parser::parse_source(&source, DEFAULT_WINDOW) {
        Ok(rules) => {
            let out = ValidateOutput {
                ok: true,
                rules: rules.len(),
                errors: vec![],
            };
            println!("{}", serde_json::to_string(&out).unwrap());
            ExitCode::from(0)
        }
        Err(msg) => {
            let out = ValidateOutput {
                ok: false,
                rules: 0,
                errors: vec![ValidateError {
                    line: extract_line(&msg).unwrap_or(0),
                    message: msg,
                }],
            };
            println!("{}", serde_json::to_string(&out).unwrap());
            ExitCode::from(1)
        }
    }
}

/// Pull a leading `line N` out of a parser error to surface as a numeric
/// field. The parser already prefixes messages this way (cf.
/// `parse_str` in the core crate); when it's missing (e.g. include
/// resolution failure) we return 0 and let callers rely on `message`.
fn extract_line(msg: &str) -> Option<u32> {
    let rest = msg.strip_prefix("line ")?;
    let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    num_str.parse().ok()
}

// =====================================================================
// simulate
// =====================================================================

#[derive(Deserialize)]
struct SimEventInput {
    module: String,
    event_type: String,
    fields: serde_json::Map<String, Value>,
}

#[derive(Serialize)]
struct ActionOut {
    kind: &'static str,
    /// Message for `Alert`, empty otherwise.
    message: String,
}

#[derive(Serialize)]
struct MatchOut {
    rule: String,
    actions: Vec<ActionOut>,
}

#[derive(Serialize)]
struct SimulateOutput {
    matched: Vec<MatchOut>,
}

fn cmd_simulate(args: &[String]) -> ExitCode {
    let rules_path = match args.first() {
        Some(s) => s,
        None => return invocation_error("simulate needs <rules.waza>"),
    };
    let event_path = match args.get(1) {
        Some(s) => s,
        None => return invocation_error("simulate needs <event.json>"),
    };

    let rules = match parser::parse_file_with_window(Path::new(rules_path), DEFAULT_WINDOW) {
        Ok(r) => r,
        Err(e) => return invocation_error(&format!("parse rules: {}", e)),
    };
    let raw = match std::fs::read_to_string(event_path) {
        Ok(s) => s,
        Err(e) => return invocation_error(&format!("read event: {}", e)),
    };
    // Accepte un objet (rétrocompat) ou un tableau d'objets. Avec un
    // tableau, les events sont rejoués dans l'ordre sur le MÊME moteur,
    // ce qui permet de tester les règles de corrélation (window).
    let inputs: Vec<SimEventInput> = match serde_json::from_str::<Value>(&raw) {
        Ok(Value::Array(_)) => match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => return invocation_error(&format!("events JSON array: {}", e)),
        },
        Ok(_) => match serde_json::from_str::<SimEventInput>(&raw) {
            Ok(v) => vec![v],
            Err(e) => return invocation_error(&format!("event JSON: {}", e)),
        },
        Err(e) => return invocation_error(&format!("event JSON: {}", e)),
    };

    let engine = RuleEngine::new(rules);
    let mut all_matches: Vec<MatchOut> = Vec::new();
    for input in inputs {
        let event = LogEvent {
            module: input.module,
            event_type: input.event_type,
            fields: flatten(&input.fields),
            timestamp: Instant::now(),
        };
        let matches = engine.process_event(&event);
        for (name, acts) in matches {
            all_matches.push(MatchOut {
                rule: name,
                actions: acts.iter().map(action_out).collect(),
            });
        }
    }
    let out = SimulateOutput { matched: all_matches };
    let ok = !out.matched.is_empty();
    println!("{}", serde_json::to_string(&out).unwrap());
    if ok { ExitCode::from(0) } else { ExitCode::from(1) }
}

fn action_out(a: &Action) -> ActionOut {
    match a {
        Action::Log => ActionOut {
            kind: "log",
            message: String::new(),
        },
        Action::Alert(m) => ActionOut {
            kind: "alert",
            message: m.clone(),
        },
        Action::KillProcess => ActionOut {
            kind: "kill",
            message: String::new(),
        },
    }
}

fn flatten(obj: &serde_json::Map<String, Value>) -> HashMap<String, FieldValue> {
    let mut out = HashMap::with_capacity(obj.len());
    for (k, v) in obj {
        if let Some(fv) = json_scalar_to_field(v) {
            out.insert(k.clone(), fv);
        }
    }
    out
}

fn json_scalar_to_field(v: &Value) -> Option<FieldValue> {
    match v {
        Value::Number(n) => n
            .as_i64()
            .map(FieldValue::Int)
            .or_else(|| n.as_f64().map(FieldValue::Float)),
        Value::String(s) => Some(FieldValue::Str(s.clone())),
        Value::Bool(b) => Some(FieldValue::Bool(*b)),
        _ => None,
    }
}

// =====================================================================
// schema
// =====================================================================

fn cmd_schema(_args: &[String]) -> ExitCode {
    // Catalogue minimal : ce que le driver émet réellement (mirroir de
    // `agent::ipc::json`). Les plugins ajoutent leurs propres champs au
    // runtime côté agent ; côté éditeur web, c'est suffisant pour
    // amorcer l'autocomplétion sur le périmètre kernel.
    let decls = vec![builtin_kernel_schema()];
    println!("{}", serde_json::to_string(&decls).unwrap());
    ExitCode::from(0)
}

// =====================================================================
// helpers
// =====================================================================

fn read_source(arg: &str) -> Result<String, String> {
    if arg == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("read stdin: {}", e))?;
        Ok(buf)
    } else {
        std::fs::read_to_string(arg).map_err(|e| format!("read {}: {}", arg, e))
    }
}

fn invocation_error(msg: &str) -> ExitCode {
    eprintln!("error: {}", msg);
    ExitCode::from(2)
}

// `Duration` is referenced by core APIs; keep this import alive even
// when the binary doesn't use it directly so dropping it later doesn't
// break the `wedr_waza_core::parser::DEFAULT_WINDOW` import chain.
#[allow(dead_code)]
fn _force_imports() -> Duration {
    DEFAULT_WINDOW
}
