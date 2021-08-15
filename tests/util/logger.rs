use fern::colors::{Color, ColoredLevelConfig};

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

lazy_static::lazy_static! {
    static ref PACKET_NUMBER: RwLock<Option<usize>> = RwLock::new(None);
}

pub fn init() {
    INIT.call_once(|| configure_logger().unwrap());
}

pub fn set_log_packet_number(packet_number: Option<usize>) {
    *PACKET_NUMBER.write().unwrap() = packet_number;
}

fn configure_logger() -> Result<(), fern::InitError> {
    fern::Dispatch::new()
        .filter(|_metadata| {
            let classifier = if ENABLED_CLASSIFIER_LOGS {
                _metadata.target().starts_with("packet_classifier")
            } else {
                false
            };

            let testing = if ENABLED_TESTING_LOGS {
                !_metadata.target().contains("packet_classifier")
            } else {
                false
            };

            classifier || testing
        })
        .format(|out, message, record| {
            let packet_number = format!(
                "{:<w$}",
                PACKET_NUMBER
                    .read()
                    .unwrap()
                    .map(|n| format!("[{}]", format!("{}", n).bright_yellow()))
                    .unwrap_or(String::new()),
                w = if PACKET_NUMBER.read().unwrap().is_some() {
                    // The console color adds extra characters that must be contemplated
                    format!("{}", format!("").bright_yellow()).len() + 4
                } else {
                    0
                }
            );

            let from_classifier = record.target().contains("packet_classifier");

            let target = record
                .target()
                .strip_prefix("packet_classifier::")
                .map(|x| String::from(x))
                .unwrap_or(
                    record
                        .target()
                        .rsplit_once("::")
                        .map(|(_, module)| String::from(module))
                        .unwrap_or(String::new()),
                );

            out.finish(format_args!(
                "{} {} {:<4} [{}]{} {}",
                format!("[{}]", chrono::Local::now().format("%M:%S:%3f")).white(), // min:sec:nano
                if !from_classifier {
                    format!(
                        "{:<spaced$}",
                        "TEST".bright_cyan(),
                        spaced = if ENABLED_CLASSIFIER_LOGS { 10 } else { 0 }
                    )
                } else {
                    format!("{}", "CLASSIFIER".yellow())
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
