use packet_classifier::core::expression::Expr;

use packet_classifier::internet::{
    self,
    tcp::expression::{TcpDestPort, TcpSourcePort},
};

mod util;
use util::{CaptureData, TestConfig};

#[test]
fn tcp_ports() {
    util::run_classification_test(TestConfig {
        loader: internet::loader(),
        config: (),
        rules: vec![
            ("DestPort80", Expr::value(TcpDestPort(80))),
            ("SourcePort80", Expr::value(TcpSourcePort(80))),
        ],
        captures: vec![CaptureData {
            name: "captures/ipv4-http-get.pcap",
            sections: vec![(1, 10)],
        }],
        expected_classification: vec![
            "DestPort80",
            "SourcePort80",
            "DestPort80",
            "DestPort80",
            "SourcePort80",
            "SourcePort80",
            "DestPort80",
            "DestPort80",
            "SourcePort80",
            "DestPort80",
        ],
    });
}
