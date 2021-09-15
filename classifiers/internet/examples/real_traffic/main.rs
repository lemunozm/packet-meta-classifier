use internet::{
    self,
    http::expression::{Http, HttpHeader, HttpMethod},
    ip::expression::IpVersion,
    tcp::expression::Tcp,
    udp::expression::Udp,
    Config,
};

use pmc_core::engine::{ClassifierEngine, Rule};
use pmc_core::expression::Expr;
use pmc_core::packet::{Direction, Packet};

use mac_address::mac_address_by_name;
use pcap::{Active, Capture, Device, Linktype};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let interface = args.get(1).expect("An interface must be specified");
    let mut network = NetworkInspector::new(interface);

    println!("Sniffing from {} interface...", interface);

    let mut classifier = ClassifierEngine::new(
        internet::loader(),
        Config::default(),
        vec![
            Rule::new("example.com", Expr::value(HttpHeader("Host", "example.com"))),
            Rule::new("Get", Expr::value(HttpMethod::Get)),
            Rule::new("Post", Expr::value(HttpMethod::Post)),
            Rule::new("Put", Expr::value(HttpMethod::Put)),
            Rule::new("Http", Expr::value(Http)),
            Rule::new("Tcp", Expr::value(Tcp)),
            Rule::new("Udp", Expr::value(Udp)),
            Rule::new("Ipv4", Expr::value(IpVersion::V4)),
            Rule::new("Ipv6", Expr::value(IpVersion::V6)),
        ],
    );

    loop {
        if let Some(packet) = network.next() {
            let classification = classifier.classify_packet(packet);
            println!(
                "{} bytes classified as: {}",
                classification.payload_bytes, classification.rule_tag
            );
        }
    }
}

struct NetworkInspector {
    capture: Capture<Active>,
    interface_mac: [u8; 6],
}

impl NetworkInspector {
    fn new(interface: &str) -> Self {
        let device = Device::list()
            .unwrap()
            .into_iter()
            .find(|device| &device.name == interface)
            .unwrap();

        let capture = Capture::from_device(device)
            .unwrap()
            .immediate_mode(true)
            .open()
            .expect(
                "You need root capabilities to run this example.\n\
            Try: 'sudo setcap cap_net_raw,cap_net_admin=eip <this-binary>'.\n\
            Error",
            );

        assert!(
            capture.get_datalink() == Linktype::ETHERNET,
            "The specified interface must be of type Ethernet"
        );

        let interface_mac = match mac_address_by_name(interface) {
            Ok(Some(interface_mac)) => interface_mac.bytes(),
            _ => panic!("The specified interface has no MAC address"),
        };

        NetworkInspector {
            capture,
            interface_mac,
        }
    }

    fn next(&mut self) -> Option<Packet<'_>> {
        let pcap_packet = self.capture.next().unwrap();
        if matches!(pcap_packet.data[12..14], [0x08, 0x00] | [0x86, 0xdd]) {
            let direction = if pcap_packet.data[0..6] == self.interface_mac {
                Direction::Downlink
            } else if pcap_packet.data[6..12] == self.interface_mac {
                Direction::Uplink
            } else {
                // The message do not belong to the expected interface
                return None;
            };

            // IP packet over ethernet.
            return Some(Packet {
                data: &pcap_packet.data[14..],
                direction,
            });
        }
        None
    }
}
