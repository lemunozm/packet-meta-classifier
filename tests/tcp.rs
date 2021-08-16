use packet_classifier::classifier::loader::AnalyzerLoader;
use packet_classifier::classifiers::tcp::expression::{TcpDestPort, TcpSourcePort};
use packet_classifier::expression::Expr;

use packet_classifier::classifiers::{ip, tcp};

mod util;
use util::{CaptureData, TestConfig};

#[test]
fn tcp_ports() {
    util::run_classification_test(TestConfig {
        loader: AnalyzerLoader::new()
            .load(ip::analyzer::IpAnalyzer::default())
            .load(tcp::analyzer::TcpAnalyzer::default()),
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
