use packet_classifier::configuration::{Configuration};
use packet_classifier::rules::expression::{Exp};
use packet_classifier::rules::classification::{ClassificationRules};
use packet_classifier::engine::{Engine};
use packet_classifier::classifiers::ip::rules::{Ip, L4};
use packet_classifier::classifiers::tcp::rules::{Tcp};

use packet_classifier::util::capture::{IpCapture};

fn main() {
    let rules = vec![
        (Exp::value(Ip::Origin("127.0.0.1".into())), 200),
        (Exp::value(Ip::L4(L4::Udp)), 100),
        (Exp::value(Ip::L4(L4::Tcp)), 300),
        (Exp::value(Ip::L4(L4::Dns)), 500),
        (Exp::or(vec![
            Exp::value(Tcp::OriginPort(3000)),
            Exp::value(Tcp::OriginPort(4000)),
        ]), 700),
        (Exp::and(vec![
            Exp::value(Tcp::OriginPort(5000)),
            Exp::value(Tcp::DestinationPort(6000)),
        ]), 800),
    ];

    let config = Configuration::new();
    let classification_rules = ClassificationRules::new(rules);
    let mut engine = Engine::new(config, classification_rules);

    let capture = IpCapture::open("captures/http.cap");
    for (index, packet) in capture[0..].iter().enumerate() {

        let classification_result = engine.process_packet(&packet.data);

        let rule: &dyn std::fmt::Display = match classification_result.rule {
            Some(rule) => rule.tag(),
            None => &"<Not matching rule>"
        };
        println!("[{}]: {}", index, rule);
    }
}

