//! `parda` — the command-line interface.

mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "parda",
    version,
    about = "Local PII filter for AI chats and agents",
    long_about = "parda replaces names, contacts, IDs and secrets with realistic stand-ins before \
text reaches a cloud AI, and puts the real values back in the answers. Everything runs on this \
machine.\n\nStart with `parda setup`, then point your agent at the proxy (`parda env claude`)."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the background daemon in the foreground (used by the service).
    Daemon {
        #[arg(long)]
        no_clipboard: bool,
        #[arg(long)]
        no_proxy: bool,
        #[arg(long)]
        no_hotkey: bool,
        /// Debug logging.
        #[arg(short, long)]
        verbose: bool,
    },
    /// Open the terminal dashboard.
    Tui {
        /// Print every tab once as plain text instead (for scripts and bug reports).
        #[arg(long)]
        dump: bool,
    },
    /// Stop the running daemon.
    Stop,
    /// Turn protection on (the default).
    On,
    /// Pause protection: text is sent unredacted until `parda on`.
    Off,
    /// Show daemon status.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Redact text (argument or `-` for stdin).
    Redact {
        text: Option<String>,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Put real values back into redacted text.
    Restore {
        text: Option<String>,
        #[arg(long)]
        scope: Option<String>,
    },
    /// List the personal data found in text.
    Scan {
        text: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Paste a redacted version of the clipboard into the focused app.
    PasteSafe,
    /// First-time setup: config, model download, service, agent settings.
    Setup {
        /// Accept defaults without asking.
        #[arg(long)]
        yes: bool,
        /// Model id to use (`none` for rules only).
        #[arg(long)]
        model: Option<String>,
        /// Do not install the login service.
        #[arg(long)]
        no_service: bool,
    },
    /// Check the installation and explain problems.
    Doctor,
    /// Manage ML models.
    #[command(subcommand)]
    Model(ModelCmd),
    /// Inspect or wipe the mapping vault.
    #[command(subcommand)]
    Vault(VaultCmd),
    /// Your own names, terms and allow-list.
    #[command(subcommand)]
    Rules(RulesCmd),
    /// Start parda at login.
    #[command(subcommand)]
    Service(ServiceCmd),
    /// The local root certificate used to protect AI websites and apps.
    #[command(subcommand)]
    Ca(CaCmd),
    /// Filter AI websites and apps: point the system proxy setting at parda.
    #[command(subcommand)]
    Intercept(InterceptCmd),
    /// Print environment settings that route an agent through parda.
    Env {
        #[arg(value_parser = ["claude", "codex", "openai", "anthropic"])]
        agent: String,
    },
}

#[derive(Subcommand)]
enum ModelCmd {
    /// Catalog and installed models.
    List,
    /// Download and verify a model.
    Pull { id: String },
    /// Make a model the default (`none` disables the ML tier).
    Use { id: String },
    /// Install a locally exported model directory (with manifest.json).
    Import {
        dir: std::path::PathBuf,
        #[arg(long, default_value = "parda-pii-edge")]
        id: String,
    },
}

#[derive(Subcommand)]
enum VaultCmd {
    /// Mapping counts by scope and kind.
    Stats,
    /// Delete mappings (all, or one scope).
    Wipe {
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Delete the vault and its key (use when the key is lost or corrupt).
    Reset {
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum RulesCmd {
    /// Print rules.toml.
    Show,
    /// Open rules.toml in $EDITOR.
    Edit,
    /// Always mask a person (name variants are added automatically).
    AddPerson {
        name: String,
        #[arg(long = "alias")]
        aliases: Vec<String>,
        #[arg(long = "email")]
        emails: Vec<String>,
        #[arg(long = "handle")]
        handles: Vec<String>,
    },
    /// Never mask this exact term.
    Allow { term: String },
}

#[derive(Subcommand)]
enum ServiceCmd {
    Install,
    Uninstall,
    Status,
}

#[derive(Subcommand)]
enum CaCmd {
    /// Create the certificate (kept in parda's data folder, key encrypted).
    Create {
        /// Replace an existing certificate (re-run `parda ca install` afterwards).
        #[arg(long)]
        force: bool,
    },
    /// Print the certificate's path.
    Path,
    /// Trust the certificate for your user (the OS asks you to confirm).
    Install,
    /// Remove it from your trust store (refused while intercept is in use).
    Uninstall {
        /// Remove it even though AI sites sent to parda will then fail to load.
        #[arg(long)]
        force: bool,
    },
    /// Show whether it exists and is trusted.
    Status,
}

#[derive(Subcommand)]
enum InterceptCmd {
    /// Start filtering AI sites (needs a trusted `parda ca`); prints how to undo.
    On,
    /// Put the previous proxy settings back and stop filtering AI sites.
    Off,
    /// Certificate, listener, system proxy and site list (changes nothing).
    Status,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Daemon {
            no_clipboard,
            no_proxy,
            no_hotkey,
            verbose,
        } => commands::daemon::run(!no_proxy, !no_clipboard, !no_hotkey, verbose),
        Command::Tui { dump } => commands::tui::run(dump),
        Command::Stop => commands::status::stop(),
        Command::On => commands::protection::set(true),
        Command::Off => commands::protection::set(false),
        Command::Status { json } => commands::status::run(json),
        Command::Redact { text, scope, json } => commands::redact::redact(text, scope, json),
        Command::Restore { text, scope } => commands::redact::restore(text, scope),
        Command::Scan { text, json } => commands::redact::scan(text, json),
        Command::PasteSafe => commands::redact::paste_safe(),
        Command::Setup {
            yes,
            model,
            no_service,
        } => commands::setup::run(yes, model, no_service),
        Command::Doctor => commands::doctor::run(),
        Command::Model(m) => match m {
            ModelCmd::List => commands::model::list(),
            ModelCmd::Pull { id } => commands::model::pull(&id),
            ModelCmd::Use { id } => commands::model::use_model(&id),
            ModelCmd::Import { dir, id } => commands::model::import(&dir, &id),
        },
        Command::Vault(v) => match v {
            VaultCmd::Stats => commands::vault::stats(),
            VaultCmd::Wipe { scope, yes } => commands::vault::wipe(scope, yes),
            VaultCmd::Reset { yes } => commands::vault::reset(yes),
        },
        Command::Rules(r) => match r {
            RulesCmd::Show => commands::rules::show(),
            RulesCmd::Edit => commands::rules::edit(),
            RulesCmd::AddPerson {
                name,
                aliases,
                emails,
                handles,
            } => commands::rules::add_person(name, aliases, emails, handles),
            RulesCmd::Allow { term } => commands::rules::allow(term),
        },
        Command::Service(s) => match s {
            ServiceCmd::Install => commands::service::install(),
            ServiceCmd::Uninstall => commands::service::uninstall(),
            ServiceCmd::Status => commands::service::status(),
        },
        Command::Ca(c) => match c {
            CaCmd::Create { force } => commands::ca::create(force),
            CaCmd::Path => commands::ca::path(),
            CaCmd::Install => commands::ca::install(),
            CaCmd::Uninstall { force } => commands::ca::uninstall(force),
            CaCmd::Status => commands::ca::status(),
        },
        Command::Intercept(i) => commands::intercept::with_system(match i {
            InterceptCmd::On => commands::intercept::on,
            InterceptCmd::Off => commands::intercept::off,
            InterceptCmd::Status => commands::intercept::status,
        }),
        Command::Env { agent } => commands::env::run(&agent),
    };
    if let Err(e) = result {
        eprintln!("parda: {e:#}");
        std::process::exit(1);
    }
}
