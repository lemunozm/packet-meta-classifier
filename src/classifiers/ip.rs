#[derive(Hash, Clone, Copy, Debug, PartialEq)]
pub enum L4 {
    Udp,
    Tcp,
    Unknown,
}

pub mod analyzer {
    use super::L4;
    use crate::analyzer::{Analyzer};
    use std::net::{IpAddr};

    pub struct IpAnalyzer {
        pub origin: Option<IpAddr>,
        pub destination: Option<IpAddr>,
        pub protocol: L4,
    }

    impl IpAnalyzer {
        pub fn new() -> IpAnalyzer {
            IpAnalyzer {
                origin: None,
                destination: None,
                protocol: L4::Unknown,
            }
        }
    }

    impl Analyzer for IpAnalyzer {
        fn analyze_packet<'a>(&mut self, data: &'a[u8]) -> &'a[u8]{
            data //TODO
        }
    }
}


pub mod rules {
    pub use super::L4;
    use crate::rules::expression::{Value};
    use crate::context::{Context};
    use std::net::{IpAddr};

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
                Ip::Origin(regex) => match ip.origin {
                    Some(origin) => regex.parse::<IpAddr>().unwrap() == origin,
                    None => false,
                }
                Ip::Destination(regex) => match ip.destination {
                    Some(destination) => regex.parse::<IpAddr>().unwrap() == destination,
                    None => false,
                }
                Ip::L4(expected_l4) => match ip.protocol {
                    L4::Tcp => *expected_l4 == L4::Tcp,
                    L4::Udp => *expected_l4 == L4::Udp,
                    L4::Unknown => *expected_l4 == L4::Unknown,
                }
            }
        }
    }
}

