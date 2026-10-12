//! `redact`, `restore`, `scan`, `paste-safe`.

use std::io::Write;

use parda_ipc::Request;
use serde_json::{Value, json};

use super::{daemon_client, hint_in_process, input_text, local_engine, paths};

fn print_text(s: &str) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_all(s.as_bytes())?;
    if !s.ends_with('\n') {
        out.write_all(b"\n")?;
    }
    Ok(())
}

pub fn redact(text: Option<String>, scope: Option<String>, json: bool) -> anyhow::Result<()> {
    let text = input_text(text)?;
    let p = paths()?;
    let result: Value = match daemon_client(&p)? {
        Some(mut c) => c.call(Request::Redact {
            text: text.clone(),
            scope: scope.clone(),
        })?,
        None => {
            hint_in_process();
            let engine = local_engine(&p)?;
            let scope = scope.unwrap_or_else(|| engine.config().clipboard.scope);
            let r = engine.redact(&text, &scope)?;
            json!({"text": r.text, "replaced": r.replaced, "warned": r.warned,
                   "ml_ms": r.ml_ms, "ml_skipped": r.ml_skipped, "paused": r.paused})
        }
    };
    if result["paused"].as_bool() == Some(true) {
        eprintln!(
            "parda: protection is OFF — text was not redacted (turn it on with `parda on` or `p` in the TUI)"
        );
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        // Keep the input's trailing newline behaviour for pipes.
        let red = result["text"].as_str().unwrap_or_default();
        if text.ends_with('\n') || !red.is_empty() {
            print_text(red)?;
        }
    }
    Ok(())
}

pub fn restore(text: Option<String>, scope: Option<String>) -> anyhow::Result<()> {
    let text = input_text(text)?;
    let p = paths()?;
    let restored = match daemon_client(&p)? {
        Some(mut c) => c.call(Request::Restore {
            text: text.clone(),
            scope,
        })?["text"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        None => {
            let engine = local_engine(&p)?;
            let scope = scope.unwrap_or_else(|| engine.config().clipboard.scope);
            engine.restore(&text, &scope)
        }
    };
    print_text(&restored)
}

pub fn scan(text: Option<String>, json: bool) -> anyhow::Result<()> {
    let text = input_text(text)?;
    let p = paths()?;
    let dets: Value = match daemon_client(&p)? {
        Some(mut c) => c.call(Request::Scan { text: text.clone() })?["detections"].clone(),
        None => {
            hint_in_process();
            serde_json::to_value(local_engine(&p)?.scan(&text)?)?
        }
    };
    let items = dets.as_array().cloned().unwrap_or_default();
    if json {
        let out: Vec<Value> = items
            .iter()
            .map(|d| {
                let (s, e) = (
                    d["span"]["start"].as_u64().unwrap_or(0) as usize,
                    d["span"]["end"].as_u64().unwrap_or(0) as usize,
                );
                json!({"kind": d["kind"], "start": s, "end": e, "text": text.get(s..e),
                       "score": d["score"], "source": d["source"]})
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }
    if items.is_empty() {
        println!("nothing sensitive found");
        return Ok(());
    }
    for d in items {
        let (s, e) = (
            d["span"]["start"].as_u64().unwrap_or(0) as usize,
            d["span"]["end"].as_u64().unwrap_or(0) as usize,
        );
        println!(
            "{:<18} {:>5}..{:<5} {:.2}  {}",
            d["kind"].as_str().unwrap_or("?"),
            s,
            e,
            d["score"].as_f64().unwrap_or(0.0),
            text.get(s..e).unwrap_or("")
        );
    }
    Ok(())
}

pub fn paste_safe() -> anyhow::Result<()> {
    let p = paths()?;
    let Some(mut c) = daemon_client(&p)? else {
        anyhow::bail!(
            "paste-safe needs the daemon: start it with `parda daemon` or `parda service install`"
        );
    };
    let r = c.call(Request::PasteSafe)?;
    match r["outcome"]
        .as_object()
        .and_then(|o| o.keys().next().cloned())
        .or_else(|| r["outcome"].as_str().map(str::to_string))
    {
        Some(k) if k == "LeftOnClipboard" => {
            eprintln!(
                "parda: could not send the paste keystroke; the redacted text is on the clipboard — paste it manually"
            );
        }
        _ => {}
    }
    Ok(())
}
