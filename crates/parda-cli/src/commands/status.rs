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
    if let Some(ents) = st["entities"].as_object()
        && !ents.is_empty()
    {
        let list: Vec<String> = ents.iter().map(|(k, v)| format!("{k} {v}")).collect();
        println!("found:     {}", list.join(", "));
    }
    Ok(())
}
