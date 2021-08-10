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
    fern::Dispatch::new()
        .filter(|metadata| metadata.target().starts_with("packet_classifier"))
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{}][{}]{}[{}]: {}",
                chrono::Local::now().format("%M:%S:%3f"), // min:sec:nano
                record.level(),
                PACKET_NUMBER
                    .read()
                    .unwrap()
                    .map(|n| format!("[{}]", n))
                    .unwrap_or(String::new()),
                record
                    .target()
                    .strip_prefix("packet_classifier::")
                    .unwrap_or(record.target()),
                message,
            ))
        })
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}
