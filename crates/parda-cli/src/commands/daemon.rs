use parda_daemon::{RunOptions, logging, run_foreground};

pub fn run(proxy: bool, clipboard: bool, hotkey: bool, verbose: bool) -> anyhow::Result<()> {
    let paths = super::paths()?;
    paths.ensure()?;
    let _guard = logging::init(&paths, verbose)?;
    run_foreground(
        paths,
        RunOptions {
            proxy,
            clipboard,
            ipc: true,
            hotkey: hotkey && clipboard,
        },
    )
}
