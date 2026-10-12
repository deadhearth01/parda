use parda_ipc::Request;

use super::{daemon_client, paths};

pub fn run(json: bool) -> anyhow::Result<()> {
    let p = paths()?;
    let Some(mut c) = daemon_client(&p)? else {
        if json {
            println!("{{\"running\": false}}");
        } else {
            println!("daemon: not running (start with `parda daemon` or `parda service install`)");
        }
        return Ok(());
    };
    let s = c.call(Request::Status)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&s)?);
        return Ok(());
    }
    println!(
        "daemon:    running (pid {}, up {} s, v{})",
        s["pid"],
        s["uptime_s"],
        s["version"].as_str().unwrap_or("?")
    );
    println!(
        "proxy:     {}",
        s["proxy"]
            .as_str()
            .map(|a| format!("http://{a}"))
            .unwrap_or_else(|| "off".into())
    );
    println!(
        "model:     {}{}",
        s["model"].as_str().unwrap_or("none"),
        s["model_error"]
            .as_str()
            .map(|e| format!("  (not loaded: {e})"))
            .unwrap_or_default()
    );
    println!("mode:      {}", s["mode"].as_str().unwrap_or("?"));
    println!(
        "clipboard: {}",
        if s["clipboard"].as_bool() == Some(true) {
            format!(
                "on (paste-safe hotkey: {})",
                s["hotkey"].as_str().unwrap_or("default")
            )
        } else {
            "off".into()
        }
    );
    let st = &s["stats"];
    println!(
        "activity:  {} redactions, {} cache hits, {} ML calls ({} failed)",
        st["redactions"], st["cache_hits"], st["ml_calls"], st["ml_failures"]
    );
    let line = |label: &str, v: &serde_json::Value| {
        if let Some(m) = v.as_object()
            && !m.is_empty()
        {
            let list: Vec<String> = m.iter().map(|(k, v)| format!("{k} {v}")).collect();
            println!("{label}{}", list.join(", "));
        }
    };
    line("found:     ", &st["entities"]);
    line("by tier:   ", &st["by_source"]);
    if let Some(surfaces) = s["activity"]["surfaces"].as_object() {
        for (name, v) in surfaces.iter().filter(|(n, _)| *n != "daemon") {
            println!(
                "{:<10} {} events, {} values redacted, {} warnings",
                format!("{name}:"),
                v["events"],
                v["redacted"],
                v["warnings"]
            );
        }
    }
    let lat = &s["activity"]["latency_ms"];
    if lat["p50"].is_u64() {
        println!(
            "latency:   p50 {} ms, p95 {} ms, max {} ms (added by parda per request)",
            lat["p50"], lat["p95"], lat["max"]
        );
    }
    Ok(())
}
