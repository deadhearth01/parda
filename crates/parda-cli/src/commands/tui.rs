pub fn run() -> anyhow::Result<()> {
    let paths = super::paths()?;
    parda_tui::run(&paths.runtime_dir)
}
