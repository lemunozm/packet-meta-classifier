use fern::colors::{Color, ColoredLevelConfig};
use std::sync::{Once, RwLock};

// Used to init the log only one time for all tests;
static INIT: Once = Once::new();

lazy_static::lazy_static! {
    static ref PACKET_NUMBER: RwLock<Option<usize>> = RwLock::new(None);
}

#[allow(dead_code)]
pub fn init() {
    INIT.call_once(|| configure_logger().unwrap());
}

#[allow(dead_code)]
pub fn set_log_packet_number(packet_number: Option<usize>) {
    *PACKET_NUMBER.write().unwrap() = packet_number;
}

fn configure_logger() -> Result<(), fern::InitError> {
    let level_colors = ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        .info(Color::Cyan)
        .debug(Color::White)
        .trace(Color::White);

    fern::Dispatch::new()
        .filter(|_metadata| {
            #[cfg(feature = "classification-logs")]
            let classification = _metadata.target().starts_with("packet_classifier");
            #[cfg(not(feature = "classification-logs"))]
            let classification = false;

            #[cfg(feature = "test-logs")]
            let test = !_metadata.target().contains("::");
            #[cfg(not(feature = "test-logs"))]
            let test = false;

            classification || test
        })
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{} {:<5} {}{}: {}",
                chrono::Local::now().format("%M:%S:%3f"), // min:sec:nano
                level_colors.color(record.level()),
                PACKET_NUMBER
                    .read()
                    .unwrap()
                    .map(|n| format!("[{}]", n))
                    .unwrap_or(String::new()),
                record
                    .target()
                    .strip_prefix("packet_classifier::")
                    .map(|n| format!(" [{}]", n))
                    .unwrap_or(String::new()),
                message,
            ))
        })
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}
