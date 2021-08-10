use packet_classifier::classifier::Classifier;
use packet_classifier::classifiers::ip::rules::IpVersion;
use packet_classifier::classifiers::tcp::rules::{Tcp, TcpSourcePort};
use packet_classifier::config::Config;
use packet_classifier::expression::Expr;

mod util;

use util::capture::Capture;

#[test]
fn basic_http_capture() {
    util::logger::init();

    let config = Config::new();

    let rules = vec![
        (Expr::value(TcpSourcePort(80)), 200),
        (Expr::value(Tcp), 300),
        (Expr::value(IpVersion::V4), 300),
    ];

    let mut classifier = Classifier::new(config, rules);

    let capture = Capture::open("captures/http.cap");
    for (index, packet) in capture[0..].iter().enumerate() {
        let classification_result = classifier.classify_packet(&packet.data);
        match classification_result.rule {
            Some(rule) => println!("[{}]: {}", index, &rule.tag),
            None => println!("[{}]: <Not matching rule>", index),
        }
    }
}
