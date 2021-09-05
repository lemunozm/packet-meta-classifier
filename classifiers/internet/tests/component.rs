mod util;
use util::capture::IpCapture;

use internet::{
    self,
    http::expression::{HttpCode, HttpHeader, HttpMethod},
    ip::expression::IpProto,
    tcp::expression::{TcpDestPort, TcpPayload, TcpSourcePort},
};

use gpc_core::expression::Expr;
use gpc_testing::common::{self, CaptureData, TestConfig};

#[test]
fn tcp_http() {
    common::run_classification_test(TestConfig {
        loader: internet::loader(),
        config: (),
        rules: vec![
            (
                "Http",
                (Expr::value(TcpDestPort(80)) | Expr::value(TcpSourcePort(80)))
                    & Expr::value(TcpPayload),
            ),
            ("D80", Expr::value(TcpDestPort(80))),
            ("S80", Expr::value(TcpSourcePort(80))),
        ],
        captures: vec![CaptureData {
            capture: IpCapture::open("tests/captures/ipv4-http-get.pcap"),
            sections: vec![(1, 10)],
        }],
        expected_classification: vec![
            "D80", "S80", "D80", "Http", "S80", "Http", "D80", "D80", "S80", "D80",
        ],
    });
}

#[test]
fn http_get() {
    common::run_classification_test(TestConfig {
        loader: internet::loader(),
        config: (),
        rules: vec![
            (
                "Get",
                Expr::value(HttpMethod::Get) & Expr::value(HttpHeader("Host", "example.com")),
            ),
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
