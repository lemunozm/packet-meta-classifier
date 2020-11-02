use packet_classifier::packet_info::{L4};
use packet_classifier::rules::rule::{Rule};
use packet_classifier::rules::values::{Ip, Tcp};
use packet_classifier::rules::classification::{ClassificationRules};

fn main() {
    let rules = vec![
        (Rule::value(Ip::Origin("127.x.x.x".into())), 200),
        (Rule::or(vec![
            Rule::value(Tcp::Teardown),
            Rule::value(Ip::L4(L4::Udp)),
        ]), 700),
        (Rule::value(Tcp::SynFlood), 400),
    ];

    let classification_rules = ClassificationRules::new(rules);
}
