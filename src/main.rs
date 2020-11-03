use packet_classifier::configuration::{Configuration};
use packet_classifier::protocols::eth::{Eth, L3};
use packet_classifier::protocols::ip::{Ip, L4};
use packet_classifier::protocols::tcp::{Tcp};
use packet_classifier::rules::rule::{Rule};
use packet_classifier::rules::classification::{ClassificationRules};
use packet_classifier::engine::{Engine};

use pcap_file::pcap::PcapReader;
use std::fs::File;

fn main() {
    let rules = vec![
        (Rule::value(Eth::L3(L3::Ip)), 100),
        (Rule::value(Ip::Origin("127.x.x.x".into())), 200),
        (Rule::or(vec![
            Rule::value(Tcp::Teardown),
            Rule::value(Ip::L4(L4::Udp)),
        ]), 700),
        (Rule::value(Tcp::SynFlood), 400),
    ];

    let config = Configuration::new();
    let classification_rules = ClassificationRules::new(rules);

    let mut engine = Engine::new(config, classification_rules);

    let pcap_file = File::open("captures/http.cap").expect("Error opening file");
    let pcap_reader = PcapReader::new(pcap_file).unwrap();

    for (index, pcap) in pcap_reader.enumerate() {
        let pcap = pcap.unwrap();
        let classification_result = engine.process_packet(&pcap.data);

        let rule: &dyn std::fmt::Display = match classification_result.rule_tag {
            Some(rule_tag) => rule_tag,
            None => &"<Not matching rule>"
        };

        println!("[{}]: {}", index, rule);
    }
}
