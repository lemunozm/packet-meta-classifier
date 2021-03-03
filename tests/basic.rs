use packet_classifier::classifiers::ip::rules::IpVersion;
use packet_classifier::classifiers::tcp::rules::{Tcp, TcpSourcePort};
use packet_classifier::config::Config;
use packet_classifier::engine::Engine;
use packet_classifier::ClassificationRules;
use packet_classifier::Exp;

mod util;

use util::capture::Capture;

#[test]
fn test() {
    util::logger::init();

    let config = Config::new();

    let rules = vec![
        (Exp::value(TcpSourcePort(80)), 200),
        (Exp::value(Tcp), 300),
        (Exp::value(IpVersion::V4), 300),
    ];

    let classification_rules = ClassificationRules::new(rules);
    let mut engine = Engine::new(config, classification_rules);

    let capture = Capture::open("captures/http.cap");
    for (index, packet) in capture[0..].iter().enumerate() {
        let classification_result = engine.process_packet(&packet.data);

        let rule: &dyn std::fmt::Display = match classification_result.rule {
            Some(rule) => &rule.tag,
            None => &"<Not matching rule>",
        };
        println!("[{}]: {}", index, rule);
    }
}
