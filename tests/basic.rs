use packet_classifier::classifiers::tcp::rules::TcpState;
use packet_classifier::Exp;

#[test]
fn test() {
    let rules = vec![(Exp::value(TcpState), 200)];

    /*
    let config = Configuration::new();
    let classification_rules = ClassificationRules::new(rules);
    let mut engine = Engine::new(config, classification_rules);

    let capture = IpCapture::open("captures/http.cap");
    for (index, packet) in capture[0..].iter().enumerate() {
        let classification_result = engine.process_packet(&packet.data);

        let rule: &dyn std::fmt::Display = match classification_result.rule {
            Some(rule) => rule.tag(),
            None => &"<Not matching rule>",
        };
        println!("[{}]: {}", index, rule);
    }
    */
}
