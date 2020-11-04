use packet_classifier::configuration::{Configuration};
use packet_classifier::rules::expression::{Exp};
use packet_classifier::rules::classification::{ClassificationRules};
use packet_classifier::engine::{Engine};
use packet_classifier::analyzers::eth::rules::{Eth, L3};
use packet_classifier::analyzers::ip::rules::{Ip, L4};
use packet_classifier::analyzers::tcp::rules::{Tcp};

use packet_classifier::util::capture::{IpCapture};

fn main() {
    let rules = vec![
        (Exp::value(Eth::L3(L3::Ip)), 100),
        (Exp::value(Ip::Origin("127.x.x.x".into())), 200),
        (Exp::or(vec![
            Exp::value(Tcp::Teardown),
            Exp::value(Ip::L4(L4::Udp)),
        ]), 700),
        (Exp::value(Tcp::SynFlood), 400),
    ];

    let config = Configuration::new();
    let classification_rules = ClassificationRules::new(rules);
    let mut engine = Engine::new(config, classification_rules);

    let capture = IpCapture::open("captures/http.cap");
    for (index, packet) in capture[0..3].iter().enumerate() {

        let classification_result = engine.process_packet(&packet.data);

        let rule: &dyn std::fmt::Display = match classification_result.rule {
            Some(rule) => rule.tag(),
            None => &"<Not matching rule>"
        };
        println!("[{}]: {}", index, rule);
    }
}

