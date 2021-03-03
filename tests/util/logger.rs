use std::sync::Once;

// Used to init the log only one time for all tests;
static INIT: Once = Once::new();

#[allow(dead_code)]
pub fn init() {
    INIT.call_once(|| configure_logger().unwrap());
}

fn configure_logger() -> Result<(), fern::InitError> {
    fern::Dispatch::new()
        .filter(|metadata| metadata.target().starts_with("packet_classifier"))
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{}][{}][{}]: {}",
                chrono::Local::now().format("%M:%S:%3f"), // min:sec:nano
                record.level(),
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
