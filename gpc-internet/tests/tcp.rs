use gpc_core::expression::Expr;

use gpc_internet::{
    self,
    tcp::expression::{TcpDestPort, TcpSourcePort},
};

use gpc_testing::common::{self, CaptureData, TestConfig};

mod util;
use util::capture::IpCapture;

#[test]
fn tcp_ports() {
    common::run_classification_test(TestConfig {
        loader: gpc_internet::loader(),
        config: (),
        rules: vec![
            ("DestPort80", Expr::value(TcpDestPort(80))),
            ("SourcePort80", Expr::value(TcpSourcePort(80))),
        ],
        captures: vec![CaptureData {
            capture: IpCapture::open("captures/ipv4-http-get.pcap"),
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
