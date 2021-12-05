extern crate tracing;

use tracing::{debug, error, info, warn};

use crate::config::ensure_config_dir;

mod cli;
mod config;
mod okta;

#[tokio::main]
async fn main() -> Result<(), ()> {
    let matches = cli::get_app()
        .try_get_matches()
        .unwrap_or_else(|e| e.exit());

    let tracing_level = if let Some(_v) = matches.values_of("verbose") {
        match _v.count() {
            1 => tracing::Level::DEBUG,
            _ => tracing::Level::TRACE,
        }
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(tracing_level)
        .with_ansi(true)
        .without_time()
        .init();

    if let Some((subcommand, sub_matches)) = matches.subcommand() {
        match subcommand {
            "init" => init(sub_matches).await?,
            "authn" => authn(sub_matches).await?,
            _ => unimplemented!(),
        }
    }

    Ok(())
}

async fn init(matches: &clap::ArgMatches) -> Result<(), ()> {
    let profile = matches.value_of("profile").ok_or(())?;
    let okta_domain = matches.value_of("okta-domain").ok_or(())?;
    let username = matches.value_of("username").ok_or(())?;

    info!("Hello, {}", username);

    // - ensure config directoy exists
    if let Err(err) = ensure_config_dir() {
        error!("Error while creating config directory: {}", err)
    }

    // - ensure config file exists
    let mut config = config::Config::new_from_file_or_empty().map_err(|err| {
        error!("Error while creating config: {}", err);
    })?;

    if let Some(_) = config.profiles.get(profile) {
        warn!("{}  profile already exists", profile);
        return Ok(());
    }

    let profile_config = config::Profile::new(okta_domain, username);

    set_password(&profile_config).map_err(|_| ())?;

    config.profiles.insert(profile.to_owned(), profile_config);

    // - append to config file
    config.save().map_err(|err| {
        error!("Error while saving config: {}", err);
    })?;

    Ok(())
}

fn set_password(profile: &config::Profile) -> Result<(), ()> {
    let keys = keyring::Keyring::new("okta-authn", &profile.keyring_name);

    debug!("reading password");
    let psswd = rpassword::prompt_password_stderr(&format!(
        "Enter password for {} on {}: ",
        profile.username, profile.domain
    ))
    .map_err(|err| {
        error!("Error while reading password: {}", err);
    })?;

    // Get password from CLI
    debug!("setting password");
    keys.set_password(&psswd).map_err(|err| {
        error!("Error while creating keyring: {}", err);
    })?;
    std::mem::drop(psswd);
    debug!("dropped password");

    Ok(())
}

async fn authn(matches: &clap::ArgMatches) -> Result<(), ()> {
    // TODO
    // Read settings from profile
    let profile = matches.value_of("profile").unwrap_or("default");
    debug!("Using profile {}", profile);

    let config = config::Config::new_from_file_or_empty().map_err(|err| {
        error!("Error while creating config: {}", err);
    })?;

    let config_profile = config.profiles.get(profile).ok_or(()).map_err(|_| {
        error!("Profile does not exist: {}", profile);
    })?;

    let _ = okta::authenticate(config_profile).await?;

    Ok(())
}

