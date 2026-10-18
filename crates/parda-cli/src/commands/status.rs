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
    if let Some(line) = intercept_line(&s["intercept"]) {
        println!("intercept: {line}");
    }
    println!(
        "model:     {}{}",
        s["model"].as_str().unwrap_or("none"),
        s["model_error"]
            .as_str()
            .map(|e| format!("  (not loaded: {e})"))
            .unwrap_or_default()
    );
    println!(
        "protection: {}",
        if s["protection"].as_bool() == Some(false) {
            "OFF (paused — `parda on` to resume)"
        } else {
            "on"
        }
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

/// The `intercept:` line from the daemon's status (`None` for a daemon that
/// does not report it).
fn intercept_line(i: &serde_json::Value) -> Option<String> {
    if !i.is_object() {
        return None;
    }
    let pac = i["pac"].is_string();
    Some(
        match (
            i["enabled"].as_bool() == Some(true),
            i["listening"].as_str(),
        ) {
            (_, Some(addr)) if pac && i["pac_matches"].as_bool() == Some(false) => format!(
                "listening on {addr}, but the system proxy points at {} — AI sites fail to \
                 load; run `parda intercept on` again",
                i["pac"].as_str().unwrap_or_default()
            ),
            (_, Some(addr)) if pac => format!("on, filtering AI sites on {addr}"),
            (_, Some(addr)) => format!(
                "listening on {addr}, but the system proxy is not set — `parda intercept on`"
            ),
            (false, None) if pac => {
                "off, but the system proxy still sends AI sites to parda — they \
                                 fail to load; run `parda intercept off`"
                    .into()
            }
            (false, None) => "off (AI websites and apps: `parda intercept on`)".into(),
            (true, None) => format!(
                "NOT LISTENING — {}{}",
                i["error"]
                    .as_str()
                    .unwrap_or("the daemon runs without its proxy services"),
                if pac {
                    "; AI sites fail to load until it listens (or `parda intercept off`)"
                } else {
                    ""
                }
            ),
        },
    )
}

pub fn stop() -> anyhow::Result<()> {
    let p = paths()?;
    match daemon_client(&p)? {
        Some(mut c) => {
            c.call(Request::Shutdown)?;
            println!("daemon stopping");
        }
        None => println!("daemon: not running"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::intercept_line;

    #[test]
    fn intercept_line_says_whether_ai_sites_are_filtered() {
        let pac = "http://127.0.0.1:8788/parda.pac";
        assert_eq!(intercept_line(&json!(null)), None, "older daemon");
        let off =
            intercept_line(&json!({"enabled": false, "listening": null, "pac": null})).unwrap();
        assert!(
            off.contains("off") && off.contains("parda intercept on"),
            "{off}"
        );
        let on =
            intercept_line(&json!({"enabled": true, "listening": "127.0.0.1:8788", "pac": pac}))
                .unwrap();
        assert!(on.contains("filtering AI sites on 127.0.0.1:8788"), "{on}");
        let no_pac =
            intercept_line(&json!({"enabled": true, "listening": "127.0.0.1:8788", "pac": null}))
                .unwrap();
        assert!(no_pac.contains("system proxy is not set"), "{no_pac}");
        let down = intercept_line(&json!({"enabled": true, "listening": null,
                                          "error": "intercept: no CA", "pac": pac}))
        .unwrap();
        assert!(
            down.contains("NOT LISTENING") && down.contains("no CA"),
            "{down}"
        );
        assert!(down.contains("fail to load"), "{down}");
        let stale =
            intercept_line(&json!({"enabled": false, "listening": null, "pac": pac})).unwrap();
        assert!(stale.contains("parda intercept off"), "{stale}");
        let moved = intercept_line(&json!({"enabled": true, "listening": "127.0.0.1:9999",
                                           "pac": pac, "pac_matches": false}))
        .unwrap();
        assert!(
            moved.contains(pac) && moved.contains("127.0.0.1:9999"),
            "{moved}"
        );
        assert!(
            moved.contains("fail to load") && moved.contains("parda intercept on"),
            "{moved}"
        );
        assert!(!moved.contains("filtering"), "{moved}");
    }
}
