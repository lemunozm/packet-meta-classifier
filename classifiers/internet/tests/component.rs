mod util;
use util::capture::IpCapture;

use internet::{
    self,
    http::expression::Http,
    tcp::expression::{Tcp, TcpDestPort, TcpSourcePort},
};

use gpc_core::expression::Expr;
use gpc_testing::common::{self, CaptureData, TestConfig};

#[test]
fn tcp_ports() {
    common::run_classification_test(TestConfig {
        loader: internet::loader(),
        config: (),
        rules: vec![
            ("DestPort80", Expr::value(TcpDestPort(80))),
            ("SourcePort80", Expr::value(TcpSourcePort(80))),
        ],
        captures: vec![CaptureData {
            capture: IpCapture::open("tests/captures/ipv4-http-get.pcap"),
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

#[test]
fn http_basics() {
    common::run_classification_test(TestConfig {
        loader: internet::loader(),
        config: (),
        rules: vec![("Http", Expr::value(Http)), ("Tcp", Expr::value(Tcp))],
        captures: vec![CaptureData {
            capture: IpCapture::open("tests/captures/ipv4-http-get.pcap"),
            sections: vec![(1, 10)],
        }],
        expected_classification: vec![
            "Tcp", "Tcp", "Tcp", "Http", "Tcp", "Http", "Tcp", "Tcp", "Tcp", "Tcp",
        ],
    });
}