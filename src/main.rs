use packet_classifier::rules::rules::{Rule, Value, Op, Tcp, L3, L4};

fn main() {
    let rules = vec![
        Rule::Op(Op::Or(vec![
            Rule::Value(Value::Tcp(Tcp::Teardown)),
            Rule::Value(Value::L4(L4::Udp)),
        ])),
        Rule::Value(Value::L4(L4::Tcp)),
        Rule::Value(Value::L3(L3::Ip)),
    ];
}
