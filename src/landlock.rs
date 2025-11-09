// Setup landlock sandboxing to given path only.

use std::process::exit;

use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus,
};

use crate::{cmdline::Cmdline, config::Config};

// Landlock only limits current thread, so it must be called before tokio runtime is created.
pub fn setup_landlock(cmdline: &Cmdline, config: &Config) -> color_eyre::Result<()> {
    let ruleset = Ruleset::default().handle_access(AccessFs::from_all(ABI::V6))?;
    let mut rules = ruleset
        .create()?
        .set_compatibility(CompatLevel::HardRequirement)
        .add_rule(PathBeneath::new(
            PathFd::new(&config.service.root)?,
            AccessFs::ReadDir,
        ))?;

    // Accessing template file
    let index_path = &cmdline
        .config
        .parent()
        .unwrap()
        .join(&config.template.index_file);
    rules = rules.add_rule(PathBeneath::new(
        PathFd::new(index_path)?,
        AccessFs::ReadFile,
    ))?;

    // Cgroup
    rules = rules
        .add_rule(PathBeneath::new(
            PathFd::new("/proc/self/cgroup")?,
            AccessFs::ReadFile,
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new("/sys/fs/cgroup")?,
            AccessFs::ReadDir | AccessFs::ReadFile,
        ))?;

    let status = rules.restrict_self()?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            tracing::info!("Landlock ruleset fully enforced");
        }
        RulesetStatus::PartiallyEnforced => {
            tracing::error!("Landlock ruleset partially enforced",);
            exit(1);
        }
        RulesetStatus::NotEnforced => {
            tracing::error!("Landlock ruleset not enforced");
            exit(1);
        }
    }
    Ok(())
}
