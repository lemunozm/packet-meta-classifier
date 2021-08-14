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
    let mut injector = Injector::new(&mut classifier, &capture);

    injector.inject_packets(1, capture.len());

    let results = injector.results().classifications.clone();
    log::info!("{}", Summary::new(classifier.rule_tags(), &results));
}
