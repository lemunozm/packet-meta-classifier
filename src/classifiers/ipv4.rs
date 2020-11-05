pub mod rules {
    pub use crate::analyzer::{L4};
    use crate::rules::expression::{Value};
    use crate::context::{Context};
    use crate::analyzer::{L3Analyzer};

    use std::net::{Ipv4Addr};

    #[derive(Debug)]
    pub enum Ipv4 {
        Origin(String),
        Destination(String),
        L4(L4),
    }

    impl Value<Context> for Ipv4 {
        fn check_value(&self, context: &Context) -> bool {
            let ip = match context.pipeline().l3() {
                L3Analyzer::Ipv4(ip) => ip,
                _ => return false
            };

            match self {
                Ipv4::Origin(regex) => match regex.parse::<Ipv4Addr>() {
                    Ok(ip_addr) => ip_addr == ip.source, //TODO regex
                    Err(_) => false,
                }
                Ipv4::Destination(regex) => match regex.parse::<Ipv4Addr>() {
                    Ok(ip_addr) => ip_addr == ip.destination, //TODO regex
                    Err(_) => false,
                }
                Ipv4::L4(expected_l4) => match ip.protocol {
                    L4::Tcp => *expected_l4 == L4::Tcp,
                    L4::Udp => *expected_l4 == L4::Udp,
                    L4::Unknown => *expected_l4 == L4::Unknown,
                }
            }
        }
    }
}

pub mod analyzer {
    use crate::analyzer::{Analyzer, L4};

    use std::net::{Ipv4Addr};

    pub struct Ipv4Analyzer {
        pub source: Ipv4Addr,
        pub destination: Ipv4Addr,
        pub protocol: L4,
    }

    impl Ipv4Analyzer {
        pub fn new() -> Ipv4Analyzer {
            Ipv4Analyzer {
                source: Ipv4Addr::UNSPECIFIED,
                destination: Ipv4Addr::UNSPECIFIED,
                protocol: L4::Unknown,
            }
        }
    }

    impl Analyzer for Ipv4Analyzer {
        fn analyze_packet<'a>(&mut self, data: &'a[u8]) -> &'a[u8]{
            self.protocol = L4::from_value(data[9]);
            self.source = Ipv4Addr::from(*array_ref![data, 12, 4]);
            self.destination = Ipv4Addr::from(*array_ref![data, 16, 4]);

            let header_length = ((data[0] & 0x0F) as usize) << 2;
            &data[header_length..] // l4 payload
        }
    }
}

