use packet_classifier::classifiers::ip::expression::IpVersion;
use packet_classifier::classifiers::tcp::expression::{Tcp, TcpSourcePort};

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
        (Expr::value(TcpSourcePort(80)), "TcpSp80"),
        (Expr::value(Tcp), "Tcp"),
        (Expr::value(IpVersion::V4), "Ipv4"),
    ];

    let mut classifier = Classifier::new(config, rules);

    let capture = Capture::open("captures/http.cap");
    let mut injector = Injector::new(&mut classifier, &capture);
    injector.inject_packets(1, capture.len());

    log::info!("{}", Summary::new(&injector.results().classifications));
}
