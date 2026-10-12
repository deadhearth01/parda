//! Environment snippets that route agents through the proxy.

use parda_daemon::load_config;

pub fn proxy_url() -> anyhow::Result<String> {
    let p = super::paths()?;
    let listen = load_config(&p)?.proxy.listen;
    // A wildcard listen address is still reached over loopback.
    let host = listen
        .replace("0.0.0.0", "127.0.0.1")
        .replace("[::]", "127.0.0.1");
    Ok(format!("http://{host}"))
}

pub fn snippet(agent: &str, url: &str) -> String {
    match agent {
        "claude" | "anthropic" => format!(
            "# Claude Code / Anthropic SDKs\nexport ANTHROPIC_BASE_URL={url}\n\n\
             # or persist it for Claude Code in ~/.claude/settings.json:\n\
             #   {{ \"env\": {{ \"ANTHROPIC_BASE_URL\": \"{url}\" }} }}"
        ),
        "codex" => format!(
            "# Codex CLI\nexport OPENAI_BASE_URL={url}/v1\n\n\
             # or in ~/.codex/config.toml:\n\
             #   [model_providers.parda]\n\
             #   name = \"OpenAI via parda\"\n\
             #   base_url = \"{url}/v1\"\n\
             #   env_key = \"OPENAI_API_KEY\"\n\
             #   wire_api = \"responses\"\n\
             #   # then: model_provider = \"parda\""
        ),
        _ => format!("# OpenAI SDKs and compatible tools\nexport OPENAI_BASE_URL={url}/v1"),
    }
}

pub fn run(agent: &str) -> anyhow::Result<()> {
    println!("{}", snippet(agent, &proxy_url()?));
    Ok(())
}
