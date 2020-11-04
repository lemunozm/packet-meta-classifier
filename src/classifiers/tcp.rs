pub mod analyzer {
    use crate::analyzer::{Analyzer};

    pub struct TcpAnalyzer {
        pub origin_port: Option<u16>,
        pub destination_port: Option<u16>,
    }

    impl TcpAnalyzer {
        pub fn new() -> TcpAnalyzer {
            TcpAnalyzer {
                origin_port: None,
                destination_port: None,
            }
        }
    }

    impl Analyzer for TcpAnalyzer {
        fn analyze_packet<'a>(&mut self, data: &'a[u8]) -> &'a[u8] {
            data //TODO
        }
    }
}

pub mod rules {
    use crate::rules::expression::{Value};
    use crate::context::{Context};
    use crate::analyzer::{L4Analyzer};

    #[derive(Debug)]
    pub enum Tcp {
        OriginPort(u16),
        DestinationPort(u16),
    }

    impl Value<Context> for Tcp {
        fn check_value(&self, context: &Context) -> bool {
            let tcp = match context.pipeline().l4() {
                L4Analyzer::Tcp(tcp) => tcp,
                _ => return false
            };

            match self {
                Tcp::OriginPort(port) => *port == tcp.origin_port.unwrap(),
                Tcp::DestinationPort(port) => *port == tcp.destination_port.unwrap(),
            }
        }
    }
}

