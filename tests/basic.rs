use packet_classifier::classifiers::ip::expression::IpVersion;
use packet_classifier::classifiers::tcp::expression::{Tcp, TcpDestPort};

use packet_classifier::config::Config;
use packet_classifier::expression::Expr;

mod util;
use util::{CaptureData, TestConfig};

#[test]
fn basic_http_capture() {
    util::run_classification_test(TestConfig {
        config: Config::new(),
        rules: vec![
            ("Tcp80", Expr::value(TcpDestPort(80))),
            ("Tcp", Expr::value(Tcp)),
            ("Ipv4", Expr::value(IpVersion::V4)),
            ("Ipv6", Expr::value(IpVersion::V6)),
        ],
        captures: vec![CaptureData {
            name: "captures/ipv6-http-get.pcap",
            sections: vec![(1, 10)],
        }],
        expected_classification: vec![
            "Tcp80", "Tcp", "Tcp80", "Tcp80", "Tcp", "Tcp", "Tcp80", "Tcp80", "Tcp", "Tcp80",
        ],
    });
}
