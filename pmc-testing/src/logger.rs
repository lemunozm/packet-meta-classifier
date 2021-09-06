use colored::Colorize;

use std::sync::{Once, RwLock};

// Used to init the log only one time for all tests;
static INIT: Once = Once::new();

#[cfg(feature = "classifier-logs")]
const ENABLED_CLASSIFIER_LOGS: bool = true;
#[cfg(not(feature = "classifier-logs"))]
const ENABLED_CLASSIFIER_LOGS: bool = false;

#[cfg(feature = "testing-logs")]
const ENABLED_TESTING_LOGS: bool = true;
#[cfg(not(feature = "testing-logs"))]
const ENABLED_TESTING_LOGS: bool = false;

#[derive(Debug, Clone)]
pub struct PacketProps {
    pub number: usize,
    pub uplink: bool,
}

lazy_static::lazy_static! {
    static ref PACKET_PROPS: RwLock<Option<PacketProps>> = RwLock::new(None);
}

pub fn init() {
    println!(); //flush everything before
    INIT.call_once(|| configure_logger().unwrap());
}

pub fn set_log_packet_number(packet_number: Option<PacketProps>) {
    *PACKET_PROPS.write().unwrap() = packet_number;
}

fn configure_logger() -> Result<(), fern::InitError> {
    let crate_name = env!("CARGO_PKG_NAME").replace("-", "_");
    fern::Dispatch::new()
        .filter({
            let crate_name = crate_name.clone();
            move |_metadata| {
                let classifier = if ENABLED_CLASSIFIER_LOGS {
                    !_metadata.target().contains(&crate_name)
                } else {
                    false
                };

                let testing = if ENABLED_TESTING_LOGS {
                    _metadata.target().starts_with(&crate_name)
                } else {
                    false
                };

                classifier || testing
            }
        })
        .format(move |out, message, record| {
            let packet_number = format!(
                "{:<w$}",
                PACKET_PROPS
                    .read()
                    .unwrap()
                    .clone()
                    .map(|PacketProps { number, uplink }| format!(
                        "[{}]",
                        format!(
                            "{} {}",
                            if uplink { "->".yellow() } else { "<-".cyan() },
                            number.to_string().bright_yellow()
                        )
                    ))
                    .unwrap_or_default(),
                w = if PACKET_PROPS.read().unwrap().is_some() {
                    // The console color adds extra characters that must be contemplated
                    format!("{}", format!("").white()).len() * 2 + 7
                } else {
                    0
                }
            );

            let from_classifier = !record.target().contains(&crate_name);

            let target = record
                .target()
                .strip_prefix("packet_classifier::")
                .map(String::from)
                .unwrap_or_else(|| {
                    record
                        .target()
                        .rsplit_once("::")
                        .map(|(_, module)| String::from(module))
                        .unwrap_or_default()
                });

            out.finish(format_args!(
                "{} {} {:<7} [{}]{} {}",
                format!("[{}]", chrono::Local::now().format("%M:%S:%3f")).white(), // min:sec:nano
                if !from_classifier {
                    format!(
                        "{:<spaced$}",
                        "TEST".bright_cyan(),
                        spaced = if ENABLED_CLASSIFIER_LOGS { 10 } else { 0 }
                    )
                } else {
                    format!("{}", "CLASSIFIER".blue())
                },
                packet_number,
                target,
                String::from(":").bright_black(),
                message,
            ))
        })
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}
