use packet_classifier::configuration::{Configuration};
use packet_classifier::rules::expression::{Exp};
use packet_classifier::rules::classification::{ClassificationRules};
use packet_classifier::engine::{Engine};
use packet_classifier::analyzers::eth::rules::{Eth, L3};
use packet_classifier::analyzers::ip::rules::{Ip, L4};
use packet_classifier::analyzers::tcp::rules::{Tcp};

use pcap_file::pcap::PcapReader;
use std::fs::File;

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

    let pcap_file = File::open("captures/http.cap").expect("Error opening file");
    let pcap_reader = PcapReader::new(pcap_file).unwrap();

    for (index, pcap) in pcap_reader.enumerate() {
        let classification_result = engine.process_packet(&pcap.unwrap().data);

        let rule: &dyn std::fmt::Display = match classification_result.rule {
            Some(rule) => rule.tag(),
            None => &"<Not matching rule>"
        };

        println!("[{}]: {}", index, rule);
    }
}
