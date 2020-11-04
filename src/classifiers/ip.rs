pub mod analyzer {
    use crate::analyzer::{Analyzer, L4};

    use std::net::{Ipv4Addr};

    impl L4 {
        fn new(protocol: u8) -> L4 {
            match protocol {
                6 => L4::Tcp,
                17 => L4::Dns,
                _ => L4::Unknown,
            }
        }
    }

    pub struct IpAnalyzer {
        pub source: Ipv4Addr,
        pub destination: Ipv4Addr,
        pub protocol: L4,
    }

    impl IpAnalyzer {
        pub fn new() -> IpAnalyzer {
            IpAnalyzer {
                source: Ipv4Addr::UNSPECIFIED,
                destination: Ipv4Addr::UNSPECIFIED,
                protocol: L4::Unknown,
            }
        }
    }

    impl Analyzer for IpAnalyzer {
        fn analyze_packet<'a>(&mut self, data: &'a[u8]) -> &'a[u8]{
            self.protocol = L4::new(data[9]);
            self.source = Ipv4Addr::from(*array_ref![data, 12, 4]);
            self.destination = Ipv4Addr::from(*array_ref![data, 16, 4]);

            let header_length = ((data[0] & 0x0F) as usize) << 2;
            &data[header_length..] // l4 payload
        }
    }
}


pub mod rules {
    pub use crate::analyzer::{L4};
    use crate::rules::expression::{Value};
    use crate::context::{Context};
    use std::net::{Ipv4Addr};

    #[derive(Debug)]
    pub enum Ip {
        Origin(String),
        Destination(String),
        L4(L4),
    }

    impl Value<Context> for Ip {
        fn check_value(&self, context: &Context) -> bool {
            let ip = context.pipeline().l3();

            match self {
                Ip::Origin(regex) => match regex.parse::<Ipv4Addr>() {
                    Ok(ip_addr) => ip_addr == ip.source, //TODO regex
                    Err(_) => false,
                }
                Ip::Destination(regex) => match regex.parse::<Ipv4Addr>() {
                    Ok(ip_addr) => ip_addr == ip.destination, //TODO regex
                    Err(_) => false,
                }
                Ip::L4(expected_l4) => match ip.protocol {
                    L4::Tcp => *expected_l4 == L4::Tcp,
                    L4::Udp => *expected_l4 == L4::Udp,
                    L4::Dns => *expected_l4 == L4::Dns,
                    L4::Unknown => *expected_l4 == L4::Unknown,
                }
            }
        }
    }
}

