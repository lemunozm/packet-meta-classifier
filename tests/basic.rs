use packet_classifier::classifier::Classifier;
use packet_classifier::classifiers::ip::rules::IpVersion;
use packet_classifier::classifiers::tcp::rules::{Tcp, TcpSourcePort};
use packet_classifier::config::Config;
use packet_classifier::expression::Expr;

mod util;

use util::capture::Capture;
use util::injector::Injector;
use util::logger;

#[test]
fn basic_http_capture() {
    logger::init();

    let config = Config::new();

    let rules = vec![
        (Expr::value(TcpSourcePort(80)), 200),
        (Expr::value(Tcp), 300),
        (Expr::value(IpVersion::V4), 400),
    ];

    let mut classifier = Classifier::new(config, rules);

    let capture = Capture::open("captures/http.cap");
    let mut injector = Injector::new(&mut classifier, &capture);
    injector.inject_packets(1, capture.len());
}
