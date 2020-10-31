use packet_classifier::rules::rules::{Rule, Value, Op, Tcp, L3, L4};
use packet_classifier::rules::classification_rules::{ClassificationRules};

fn main() {
    let rules = vec![
        (1, Rule::Op(Op::Or(vec![
            Rule::Value(Value::Tcp(Tcp::Teardown)),
            Rule::Value(Value::L4(L4::Udp)),
        ]))),
        (2, Rule::Value(Value::L4(L4::Tcp))),
        (3, Rule::Value(Value::L3(L3::Ip))),
    ];

    let classification_rules = ClassificationRules::new(rules);
}
