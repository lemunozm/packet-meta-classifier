use packet_classifier::classifiers::ip::expression::IpVersion;
use packet_classifier::classifiers::tcp::expression::{Tcp, TcpDestPort};

use packet_classifier::classifier::Classifier;
use packet_classifier::config::Config;
use packet_classifier::expression::Expr;

mod util;
use util::{logger, Capture, Injector, Summary};

#[test]
fn basic_http_capture() {
    logger::init();

    let config = Config::new();

    let rules = vec![
        ("Tcp80", Expr::value(TcpDestPort(80))),
        ("Tcp", Expr::value(Tcp)),
        ("Ipv4", Expr::value(IpVersion::V4)),
        ("Ipv6", Expr::value(IpVersion::V6)),
    ];

    let mut classifier = Classifier::new(config, rules);

    let capture = Capture::open("captures/ipv6-http-get.pcap");
    let mut injector = Injector::new(&capture);

    let results = injector.inject_packets(&mut classifier, 1, capture.len());
    assert_eq!(
        results,
        vec!["Tcp80", "Tcp", "Tcp80", "Tcp80", "Tcp", "Tcp", "Tcp80", "Tcp80", "Tcp", "Tcp80"]
    );

    log::info!(
        "{}",
        Summary::new(classifier.rule_tags(), &results.classifications)
    );
}
