mod util;
use util::capture::IpCapture;

use internet::{
    self,
    http::expression::{HttpCode, HttpHeader, HttpMethod},
    ip::expression::IpProto,
    tcp::expression::{
        TcpDestPort, TcpEstablished, TcpHandshake, TcpPayloadLen, TcpServerPort, TcpSourcePort,
        TcpTeardown,
    },
    udp::expression::{UdpDestPort, UdpPayloadLen, UdpSourcePort},
};

use pmc_core::expression::Expr;
use pmc_testing::common::{self, CaptureData, TestConfig};

#[test]
fn udp_echo() {
    common::run_classification_test(TestConfig {
        loader: internet::loader(),
        config: (),
        rules: vec![
            ("MoreThan10B", Expr::value(UdpPayloadLen(|len| len > 10))),
            ("ToServer", Expr::value(UdpDestPort(12345))),
            ("ToClient", Expr::value(UdpSourcePort(12345))),
        ],
        captures: vec![CaptureData {
            capture: IpCapture::open("tests/captures/ipv4-udp-echo.pcap"),
            sections: vec![(1, 4)],
        }],
        expected_classification: vec!["ToServer", "ToClient", "MoreThan10B", "MoreThan10B"],
    });
}

#[test]
fn tcp_http() {
    common::run_classification_test(TestConfig {
        loader: internet::loader(),
        config: (),
        rules: vec![
            (
                "Http",
                Expr::value(TcpServerPort(80)) & Expr::value(TcpPayloadLen(|len| len > 0)),
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
fn tcp_established() {
    common::run_classification_test(TestConfig {
        loader: internet::loader(),
        config: (),
        rules: vec![
            ("Handshake", Expr::value(TcpHandshake)),
            ("Established", Expr::value(TcpEstablished)),
            ("Teardown", Expr::value(TcpTeardown)),
        ],
        captures: vec![CaptureData {
            capture: IpCapture::open("tests/captures/ipv4-http-get.pcap"),
            sections: vec![(1, 10)],
        }],
        expected_classification: vec![
            "Handshake",
            "Handshake",
            "Handshake",
            "Established",
            "Established",
            "Established",
            "Established",
            "Teardown",
            "Teardown",
            "Teardown",
        ],
    });
}

#[test]
fn tcp_midflow() {
    common::run_classification_test(TestConfig {
        loader: internet::loader(),
        config: (),
        rules: vec![("MidFlow", !Expr::value(TcpEstablished))],
        captures: vec![CaptureData {
            capture: IpCapture::open("tests/captures/ipv4-http-get.pcap"),
            sections: vec![(2, 5)],
        }],
        expected_classification: vec!["MidFlow", "MidFlow", "MidFlow", "MidFlow"],
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
