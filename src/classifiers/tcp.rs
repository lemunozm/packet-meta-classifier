pub mod analyzer {
    use crate::analyzer::{Analyzer};

    pub struct TcpAnalyzer {
        pub source_port: u16,
        pub destination_port: u16,
    }

    impl TcpAnalyzer {
        pub fn new() -> TcpAnalyzer {
            TcpAnalyzer {
                source_port: 0,
                destination_port: 0,
            }
        }
    }

    impl Analyzer for TcpAnalyzer {
        fn analyze_packet<'a>(&mut self, data: &'a[u8]) -> &'a[u8] {
            self.source_port = u16::from_be_bytes(*array_ref![data, 0, 2]);
            self.destination_port = u16::from_be_bytes(*array_ref![data, 0, 2]);
            data
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
                Tcp::OriginPort(port) => *port == tcp.source_port,
                Tcp::DestinationPort(port) => *port == tcp.destination_port,
            }
        }
    }
}

