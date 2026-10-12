pub fn run(dump: bool) -> anyhow::Result<()> {
    let paths = super::paths()?;
    if dump {
        print!("{}", parda_tui::dump(&paths.runtime_dir, 110, 30)?);
        return Ok(());
    }
    parda_tui::run(&paths.runtime_dir)
}
