mod util;
use util::capture::IpCapture;

use internet::{
    self,
    http::expression::{HttpCode, HttpMethod},
    ip::expression::IpProto,
    tcp::expression::{TcpDestPort, TcpSourcePort},
};

use gpc_core::expression::Expr;
use gpc_testing::common::{self, CaptureData, TestConfig};

#[test]
fn tcp_ports() {
    common::run_classification_test(TestConfig {
        loader: internet::loader(),
        config: (),
        rules: vec![
            ("D80", Expr::value(TcpDestPort(80))),
            ("S80", Expr::value(TcpSourcePort(80))),
        ],
        captures: vec![CaptureData {
            capture: IpCapture::open("tests/captures/ipv4-http-get.pcap"),
            sections: vec![(1, 10)],
        }],
        expected_classification: vec![
            "D80", "S80", "D80", "D80", "S80", "S80", "D80", "D80", "S80", "D80",
        ],
    });
}

#[test]
fn http_basics() {
    common::run_classification_test(TestConfig {
        loader: internet::loader(),
        config: (),
        rules: vec![
            ("Get", Expr::value(HttpMethod::Get)),
            ("200OK", Expr::value(HttpCode("200"))),
            ("Tcp", Expr::value(IpProto::Tcp)),
        ],
        captures: vec![CaptureData {
            capture: IpCapture::open("tests/captures/ipv4-http-get.pcap"),
            sections: vec![(1, 10)],
        }],
        expected_classification: vec![
            "Tcp", "Tcp", "Tcp", "Get", "Tcp", "200OK", "Tcp", "Tcp", "Tcp", "Tcp",
        ],
    });
}
