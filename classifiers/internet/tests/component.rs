mod util;
use util::capture::IpCapture;

use internet::{
    self,
    http::expression::{HttpCode, HttpHeader, HttpMethod, HttpRequest, HttpResponse},
    tcp::expression::{
        Tcp, TcpDestPort, TcpEstablished, TcpHandshake, TcpPayloadLen, TcpRetransmission,
        TcpServerPort, TcpSourcePort, TcpTeardown,
    },
    udp::expression::{UdpDestPort, UdpPayloadLen, UdpSourcePort},
    Config,
};

use pmc_core::engine::Rule;
use pmc_core::expression::Expr;

use pmc_testing::common::{self, CaptureData, TestConfig};

#[test]
fn udp_echo() {
    common::run_classification_test(TestConfig {
        loader: internet::loader(),
        config: Config::default(),
        rules: vec![
            Rule::new("MoreThan10Bytes", Expr::value(UdpPayloadLen(|len| len > 10))),
            Rule::new("ToServer", Expr::value(UdpDestPort(12345))),
            Rule::new("ToClient", Expr::value(UdpSourcePort(12345))),
        ],
        captures: vec![CaptureData {
            capture: IpCapture::open("tests/captures/ipv4-udp-echo.pcap"),
            sections: vec![(1, 4)],
        }],
        expected_classification: vec!["ToServer", "ToClient", "MoreThan10Bytes", "MoreThan10Bytes"],
    });
}

#[test]
fn tcp_http() {
    common::run_classification_test(TestConfig {
        loader: internet::loader(),
        config: Config::default(),
        rules: vec![
            Rule::new(
                "Http?",
                Expr::value(TcpServerPort(80)) & Expr::value(TcpPayloadLen(|len| len > 0)),
            ),
            Rule::new("D80", Expr::value(TcpDestPort(80))),
            Rule::new("S80", Expr::value(TcpSourcePort(80))),
        ],
        captures: vec![CaptureData {
            capture: IpCapture::open("tests/captures/ipv4-http-get.pcap"),
            sections: vec![(1, 10)],
        }],
        expected_classification: vec![
            "D80", "S80", "D80", "Http?", "S80", "Http?", "D80", "D80", "S80", "D80",
        ],
    });
}

#[test]
fn tcp_established() {
    common::run_classification_test(TestConfig {
        loader: internet::loader(),
        config: Config::default(),
        rules: vec![
            Rule::new("Retransmision", Expr::value(TcpRetransmission)),
            Rule::new("Handshake", Expr::value(TcpHandshake)),
            Rule::new("Established", Expr::value(TcpEstablished)),
            Rule::new("Teardown", Expr::value(TcpTeardown)),
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
fn tcp_retransmission() {
    common::run_classification_test(TestConfig {
        loader: internet::loader(),
        config: Config::default(),
        rules: vec![
            Rule::new("Retransmision", Expr::value(TcpRetransmission)),
            Rule::new("Handshake", Expr::value(TcpHandshake)),
            Rule::new("Established", Expr::value(TcpEstablished)),
            Rule::new("Teardown", Expr::value(TcpTeardown)),
        ],
        captures: vec![CaptureData {
            capture: IpCapture::open("tests/captures/ipv4-http-get.pcap"),
            sections: vec![(1, 6), (6, 10)],
        }],
        expected_classification: vec![
            "Handshake",
            "Handshake",
            "Handshake",
            "Established",
            "Established",
            "Established",
            "Retransmision",
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
        config: Config::default(),
        rules: vec![Rule::new("MidFlow", !Expr::value(TcpEstablished))],
        captures: vec![CaptureData {
            capture: IpCapture::open("tests/captures/ipv4-http-get.pcap"),
            sections: vec![(2, 5)],
        }],
        expected_classification: vec!["MidFlow", "MidFlow", "MidFlow", "MidFlow"],
    });
}

#[test]
fn http_request_response() {
    common::run_classification_test(TestConfig {
        loader: internet::loader(),
        config: Config::default(),
        rules: vec![
            Rule::new("REQ", Expr::value(HttpRequest)),
            Rule::new("RES", Expr::value(HttpResponse)),
            Rule::new("Established", Expr::value(TcpEstablished)),
            Rule::new("Tcp", Expr::value(Tcp)),
        ],
        captures: vec![CaptureData {
            capture: IpCapture::open("tests/captures/ipv4-http-get.pcap"),
            sections: vec![(1, 10)],
        }],
        expected_classification: vec![
            "Tcp",
            "Tcp",
            "Established",
            "REQ",
            "Established",
            "RES",
            "Established",
            "Tcp",
            "Tcp",
            "Tcp",
        ],
    });
}

#[test]
fn http_get() {
    common::run_classification_test(TestConfig {
        loader: internet::loader(),
        config: Config::default(),
        rules: vec![
            Rule::new(
                "GET",
                Expr::value(HttpMethod::Get) & Expr::value(HttpHeader("Host", "example.com")),
            ),
            Rule::new(
                "200OK",
                Expr::value(HttpCode("200")) & Expr::value(HttpHeader("Content-Type", "text/html")),
            ),
            Rule::new("Tcp", Expr::value(Tcp)),
        ],
        captures: vec![CaptureData {
            capture: IpCapture::open("tests/captures/ipv4-http-get.pcap"),
            sections: vec![(1, 10)],
        }],
        expected_classification: vec![
            "Tcp", "Tcp", "Tcp", "GET", "Tcp", "200OK", "Tcp", "Tcp", "Tcp", "Tcp",
        ],
    });
}
