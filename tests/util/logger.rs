use fern::colors::{Color, ColoredLevelConfig};

use colored::Colorize;

use std::sync::{Once, RwLock};

// Used to init the log only one time for all tests;
static INIT: Once = Once::new();

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
    let level_colors = ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        .info(Color::BrightCyan)
        .debug(Color::Magenta)
        .trace(Color::White);

    fern::Dispatch::new()
        .filter(|_metadata| {
            #[cfg(feature = "classification-logs")]
            let classification = _metadata.target().starts_with("packet_classifier");
            #[cfg(not(feature = "classification-logs"))]
            let classification = false;

            #[cfg(feature = "framework-logs")]
            let framework = !_metadata.target().contains("packet_classifier");
            #[cfg(not(feature = "framework-logs"))]
            let framework = false;

            classification || framework
        })
        .format(move |out, message, record| {
            let packet_number = format!(
                "{:<w$}",
                PACKET_NUMBER
                    .read()
                    .unwrap()
                    .map(|n| format!("[{}]", n))
                    .unwrap_or(String::new()),
                w = if PACKET_NUMBER.read().unwrap().is_some() {
                    4
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
                    if cfg!(feature = "classification-logs") {
                        format!("{:<10}", "TEST".bright_cyan())
                    } else {
                        format!("{}", "TEST".bright_cyan())
                    }
                } else {
                    format!("{}", "CLASSIFIER".white())
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
