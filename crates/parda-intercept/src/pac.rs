//! The proxy auto-config file: listed hosts go to parda, everything else DIRECT.

use std::net::SocketAddr;

use crate::HostList;

/// A JavaScript PAC returning `PROXY <proxy>` for listed hosts (and their
/// subdomains) and `DIRECT` for everything else.
///
/// A listed host gets no `DIRECT` fallback: if parda stops while a browser
/// still holds this PAC, AI requests fail instead of leaving unfiltered.
pub fn pac(hosts: &HostList, proxy: SocketAddr) -> String {
    // Entries are restricted to [a-z0-9.-] by HostList, so quoting is safe.
    let list = hosts
        .entries()
        .iter()
        .map(|h| format!("\"{h}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"// parda: send AI hosts through the local PII filter, everything else DIRECT.
var PARDA_HOSTS = [{list}];
function FindProxyForURL(url, host) {{
  var h = host.toLowerCase();
  if (h.charAt(h.length - 1) === ".") h = h.substring(0, h.length - 1);
  for (var i = 0; i < PARDA_HOSTS.length; i++) {{
    var e = PARDA_HOSTS[i];
    if (h === e || (h.length > e.length && h.substring(h.length - e.length - 1) === "." + e)) {{
      return "PROXY {proxy}";
    }}
  }}
  return "DIRECT";
}}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> String {
        let hosts = HostList::new(&["chat.test".to_string(), "claude.ai".to_string()]);
        pac(&hosts, "127.0.0.1:8788".parse().unwrap())
    }

    #[test]
    fn pac_names_the_hosts_and_the_proxy() {
        let p = sample();
        assert!(p.contains("function FindProxyForURL(url, host)"));
        assert!(p.contains("\"chat.test\""));
        assert!(p.contains("\"claude.ai\""));
        assert!(p.contains("\"PROXY 127.0.0.1:8788\""));
        assert!(p.contains("\"DIRECT\""));
    }

    /// Evaluate the PAC with node when it is installed (CI images and dev
    /// machines have it); the textual checks above always run.
    #[test]
    fn pac_routes_listed_hosts_and_subdomains_only() {
        let p = sample();
        let mut script = p.clone();
        script.push_str(
            "\nfor (const h of ['chat.test','x.chat.test','CHAT.TEST','api.claude.ai',\
             'example.com','evilchat.test','chat.test.evil.com']) \
             console.log(h + '=' + FindProxyForURL('https://' + h + '/', h));\n\
             for (const u of ['http://chat.test/', 'wss://chat.test/', 'ws://chat.test/', \
             'HTTPS://x.chat.test/', 'ftp://chat.test/']) \
             console.log(u + '=' + FindProxyForURL(u, u.split('/')[2]));\n",
        );
        let out = match std::process::Command::new("node")
            .arg("-e")
            .arg(&script)
            .output()
        {
            Ok(o) => {
                let err = String::from_utf8_lossy(&o.stderr);
                assert!(o.status.success(), "PAC failed to evaluate: {err}");
                String::from_utf8(o.stdout).unwrap()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("node not installed; PAC evaluation skipped");
                return;
            }
            Err(e) => panic!("running node: {e}"),
        };
        let proxy = "PROXY 127.0.0.1:8788";
        for (h, want) in [
            ("chat.test", proxy),
            ("x.chat.test", proxy),
            ("CHAT.TEST", proxy),
            ("api.claude.ai", proxy),
            ("example.com", "DIRECT"),
            ("evilchat.test", "DIRECT"),
            ("chat.test.evil.com", "DIRECT"),
            // Only TLS URLs go to parda; plain http stays DIRECT so the site
            // can redirect to https.
            ("http://chat.test/", "DIRECT"),
            ("wss://chat.test/", proxy),
            ("ws://chat.test/", "DIRECT"),
            ("HTTPS://x.chat.test/", proxy),
            ("ftp://chat.test/", "DIRECT"),
        ] {
            assert!(out.contains(&format!("{h}={want}\n")), "{h}: {out}");
        }
    }
}
