use clap::{App, Arg};

pub(crate) fn get_app() -> App<'static> {
    App::new("okta-authn")
        .version("0.1.0")
        .author("")
        .about("Authneticates to Okta from CLI")
        .arg(
            Arg::new("config")
                .long("config")
                .short('c')
                .value_name("CONFIG_FILE")
                .about("Sets a custom config file")
                .takes_value(true),
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .short('v')
                .multiple_occurrences(true)
                .about("Sets the level of verbosity"),
        )
        .subcommand(
            App::new("init")
                .about("initial setup of tool")
                .arg(
                    Arg::new("profile")
                        .long("profile")
                        .short('p')
                        .about("Name of profile to configure")
                        .default_value("default")
                        .takes_value(true),
                )
                .arg(
                    Arg::new("okta-domain")
                        .long("domain")
                        .short('d')
                        .about("Okta domain to authneticate to (e.g. example.okta.com)")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::new("username")
                        .long("username")
                        .short('u')
                        .about("Username to authenticate with")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .subcommand(
            App::new("authn")
                .about("initial setup of tool")
                .arg(
                    Arg::new("profile")
                        .long("profile")
                        .short('p')
                        .about("Name of profile to use")
                        .default_value("default")
                        .takes_value(true),
                )
        )
}
