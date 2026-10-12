//! `parda rules show | edit | add-person | allow`.

use parda_daemon::{load_rules, write_private};
use parda_detect::{PersonBlock, RulesFile};
use parda_ipc::Request;

use super::{daemon_client, paths};

const HEADER: &str = "# parda rules — names and terms to always mask, and terms never to mask.\n\
# [[person]] name = \"Ravi Kumar\"  aliases = [\"RK\"]  emails = [...]  handles = [\"@ravik\"]\n\
# [[term]] text = \"Project Falcon\"  kind = \"Organization\"\n\
# allow = [\"Acme Corp\"]\n\n";

/// Save rules and tell a running daemon.
fn save(rules: &RulesFile) -> anyhow::Result<()> {
    let p = paths()?;
    let toml = rules.to_toml_string()?;
    match daemon_client(&p)? {
        Some(mut c) => {
            c.call(Request::RulesSet { rules_toml: toml })?;
        }
        None => {
            p.ensure()?;
            write_private(&p.rules_file(), &format!("{HEADER}{toml}"))?;
        }
    }
    Ok(())
}

pub fn show() -> anyhow::Result<()> {
    let p = paths()?;
    let rules = load_rules(&p)?;
    println!("# {}", p.rules_file().display());
    print!("{}", rules.to_toml_string()?);
    Ok(())
}

pub fn edit() -> anyhow::Result<()> {
    let p = paths()?;
    p.ensure()?;
    let file = p.rules_file();
    if !file.exists() {
        write_private(&file, HEADER)?;
    }
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| {
            if cfg!(windows) {
                "notepad".into()
            } else {
                "vi".into()
            }
        });
    let status = std::process::Command::new(&editor).arg(&file).status()?;
    if !status.success() {
        anyhow::bail!("{editor} exited with {status}");
    }
    let rules = load_rules(&p)?; // validate
    if let Some(mut c) = daemon_client(&p)? {
        c.call(Request::RulesSet {
            rules_toml: rules.to_toml_string()?,
        })?;
    }
    println!(
        "rules saved ({} people, {} terms, {} allowed)",
        rules.person.len(),
        rules.term.len(),
        rules.allow.len()
    );
    Ok(())
}

pub fn add_person(
    name: String,
    aliases: Vec<String>,
    emails: Vec<String>,
    handles: Vec<String>,
) -> anyhow::Result<()> {
    let p = paths()?;
    let mut rules = load_rules(&p)?;
    if let Some(existing) = rules
        .person
        .iter_mut()
        .find(|b| b.name.eq_ignore_ascii_case(name.trim()))
    {
        existing.aliases.extend(aliases);
        existing.emails.extend(emails);
        existing.handles.extend(handles);
    } else {
        rules.person.push(PersonBlock {
            name: name.trim().to_string(),
            aliases,
            emails,
            handles,
        });
    }
    save(&rules)?;
    let variants = parda_detect::expand_person(rules.person.last().expect("just added"));
    println!("added {} ({} variants masked)", name.trim(), variants.len());
    Ok(())
}

pub fn allow(term: String) -> anyhow::Result<()> {
    let p = paths()?;
    let mut rules = load_rules(&p)?;
    if !rules
        .allow
        .iter()
        .any(|a| a.eq_ignore_ascii_case(term.trim()))
    {
        rules.allow.push(term.trim().to_string());
    }
    save(&rules)?;
    println!("`{}` will never be masked", term.trim());
    Ok(())
}
