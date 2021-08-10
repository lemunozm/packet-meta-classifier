use packet_classifier::classifier::Classifier;
use packet_classifier::classifiers::ip::rules::IpVersion;
use packet_classifier::classifiers::tcp::rules::{Tcp, TcpSourcePort};
use packet_classifier::config::Config;
use packet_classifier::expression::Expr;

mod util;

use util::capture::Capture;
use util::logger;

#[test]
fn basic_http_capture() {
    logger::init();

    let config = Config::new();

    let rules = vec![
        (Expr::value(TcpSourcePort(80)), 200),
        (Expr::value(Tcp), 300),
        (Expr::value(IpVersion::V4), 400),
    ];

    let mut classifier = Classifier::new(config, rules);

    let capture = Capture::open("captures/http.cap");
    for (index, packet) in capture[0..].iter().enumerate() {
        let packet_number = index + 1;
        logger::set_log_packet_number(Some(packet_number));
        let classification_result = classifier.classify_packet(&packet.data);
        match classification_result.rule {
            Some(rule) => println!("[{}]: {}", packet_number, &rule.tag),
            None => println!("[{}]: <Not matching rule>", packet_number),
        }
    }

    logger::set_log_packet_number(None);
}
