use crate::Config;

use pmc_core::base::classifier::Classifier;

pub struct HttpStartLineClassifier;
impl<'a> Classifier<'a, Config> for HttpStartLineClassifier {
    type Analyzer = analyzer::HttpStartLineAnalyzer<'a>;
}

pub struct HttpHeaderClassifier;
impl<'a> Classifier<'a, Config> for HttpHeaderClassifier {
    type Analyzer = analyzer::HttpHeaderAnalyzer<'a>;
}

mod analyzer {
    use super::flow::{HttpFlow, State};

    use crate::{ClassifierId, Config, FlowSignature};

    use pmc_core::base::analyzer::{Analyzer, AnalyzerInfo, AnalyzerResult, BuildFlow};
    use pmc_core::packet::{Direction, Packet};

    use std::convert::TryFrom;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Method {
        Get,
        Head,
        Post,
        Put,
        Delete,
        Connect,
        Options,
        Trace,
        Patch,
    }

    impl TryFrom<&str> for Method {
        type Error = ();
        fn try_from(value: &str) -> Result<Self, ()> {
            match value {
                "GET" => Ok(Self::Get),
                "DELETE" => Ok(Self::Delete),
                "CONNECT" => Ok(Self::Connect),
                "OPTIONS" => Ok(Self::Options),
                "TRACE" => Ok(Self::Trace),
                "HEAD" => Ok(Self::Head),
                "POST" => Ok(Self::Post),
                "PUT" => Ok(Self::Put),
                "PATCH" => Ok(Self::Patch),
                _ => Err(()),
            }
        }
    }

    enum StartLine<'a> {
        Request {
            version: &'a str,
            method: &'a str,
            uri: &'a str,
        },
        Response {
            code: &'a str,
            text: &'a str,
            version: &'a str,
        },
        Unknown,
    }

    pub struct HttpStartLineAnalyzer<'a> {
        start_line: StartLine<'a>,
    }

    impl<'a> HttpStartLineAnalyzer<'a> {
        const START_LINE_MALFORMED: &'static str = "Http start line malformed";

        pub fn method(&self) -> Option<Method> {
            match self.start_line {
                StartLine::Request { method, .. } => Method::try_from(method).ok(),
                _ => None,
            }
        }

        pub fn uri(&self) -> Option<&str> {
            match self.start_line {
                StartLine::Request { uri, .. } => Some(uri),
                _ => None,
            }
        }

        pub fn is_request(&self) -> bool {
            matches!(self.start_line, StartLine::Request { .. })
        }

        pub fn is_response(&self) -> bool {
            matches!(self.start_line, StartLine::Response { .. })
        }

        pub fn code(&self) -> Option<&str> {
            match self.start_line {
                StartLine::Response { code, .. } => Some(code),
                _ => None,
            }
        }

        pub fn text_code(&self) -> Option<&str> {
            match self.start_line {
                StartLine::Response { text, .. } => Some(text),
                _ => None,
            }
        }

        pub fn version(&self) -> Option<&str> {
            match self.start_line {
                StartLine::Request { version, .. } => Some(version),
                StartLine::Response { version, .. } => Some(version),
                _ => None,
            }
        }
    }

    impl<'a> Analyzer<'a, Config> for HttpStartLineAnalyzer<'a> {
        const ID: ClassifierId = ClassifierId::HttpStartLine;
        const PREV_ID: ClassifierId = ClassifierId::Tcp;

        type Flow = HttpFlow;

        fn update_flow_id(_signature: &mut FlowSignature, _packet: &Packet) -> BuildFlow {
            BuildFlow::Yes
        }

        fn build(
            _config: &Config,
            &Packet { data, direction }: &'a Packet,
            flow: &HttpFlow,
        ) -> AnalyzerResult<Self, ClassifierId> {
            let header = unsafe {
                //SAFETY: We only check againts first 128 ascii values
                std::str::from_utf8_unchecked(data)
            };

            let parse_line: Option<(StartLine, &str)> = (|| {
                let mut iter = header.splitn(3, ' ');
                let first = iter.next()?;
                let second = iter.next()?;
                let third_and_more = iter.next()?;
                let (third, next_data) = third_and_more.split_once("\r\n")?;

                let start_line = match direction {
                    Direction::Uplink => StartLine::Request {
                        method: first,
                        uri: second,
                        version: third,
                    },
                    Direction::Downlink => StartLine::Response {
                        version: first,
                        code: second,
                        text: third,
                    },
                };

                Some((start_line, next_data))
            })();

            let (start_line, next_data) = match parse_line {
                Some((start_line, next_data)) => (start_line, next_data),
                None => {
                    if let State::Unknown = flow.state {
                        return Err(Self::START_LINE_MALFORMED);
                    }
                    (StartLine::Unknown, &header[header.len() - 1..])
                }
            };

            Ok(AnalyzerInfo {
                analyzer: Self { start_line },
                next_classifier_id: ClassifierId::HttpHeader,
                bytes_parsed: next_data.as_ptr() as usize - data.as_ptr() as usize,
            })
        }

        fn update_flow(&self, _config: &Config, flow: &mut HttpFlow, _direction: Direction) {
            match self.start_line {
                StartLine::Request { .. } => flow.state = State::Request,
                StartLine::Response { .. } => flow.state = State::Response,
                StartLine::Unknown => (),
            }
        }
    }

    pub struct HttpHeaderAnalyzer<'a> {
        headers: &'a str,
    }

    impl<'a> HttpHeaderAnalyzer<'a> {
        pub fn find_header(&self, expected_key: &str) -> Option<&str> {
            let mut content = self.headers;
            loop {
                match content.split_once("\r\n") {
                    Some((header_line, next)) => match header_line.split_once(": ") {
                        Some((key, value)) => {
                            if key == expected_key {
                                break Some(value);
                            }
                            content = next;
                        }
                        None => break None,
                    },
                    None => break None,
                }
            }
        }
    }

    impl<'a> Analyzer<'a, Config> for HttpHeaderAnalyzer<'a> {
        const ID: ClassifierId = ClassifierId::HttpHeader;
        const PREV_ID: ClassifierId = ClassifierId::HttpStartLine;

        type Flow = HttpFlow;

        fn update_flow_id(_signature: &mut FlowSignature, _packet: &Packet) -> BuildFlow {
            BuildFlow::Yes
        }

        fn build(
            _config: &Config,
            &Packet { data, .. }: &'a Packet,
            _flow: &HttpFlow,
        ) -> AnalyzerResult<Self, ClassifierId> {
            let headers = unsafe {
                //SAFETY: We only check againts first 128 ascii values
                std::str::from_utf8_unchecked(data)
            };

            let header_len = headers
                .find("\r\n\r\n")
                .ok_or("Malformed HTTP header in headers section")?
                + 4; //because of "\r\n\r\n"

            Ok(AnalyzerInfo {
                analyzer: Self { headers },
                next_classifier_id: ClassifierId::None,
                bytes_parsed: header_len,
            })
        }

        fn update_flow(&self, _config: &Config, _flow: &mut HttpFlow, _direction: Direction) {}
    }
}

mod flow {
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum State {
        Request,
        Response,
        Unknown,
    }

    pub struct HttpFlow {
        pub state: State,
    }

    impl Default for HttpFlow {
        fn default() -> Self {
            Self {
                state: State::Unknown,
            }
        }
    }
}

pub mod expression {
    use super::analyzer::{HttpHeaderAnalyzer, HttpStartLineAnalyzer};
    use super::flow::{HttpFlow, State};

    use crate::Config;

    use pmc_core::base::expression_value::ExpressionValue;

    #[derive(Debug)]
    pub struct Http;
    impl ExpressionValue<Config> for Http {
        type Classifier = super::HttpStartLineClassifier;

        const SHOULD_GRANT_BY_FLOW: bool = true;

        fn check(&self, _packet: &HttpStartLineAnalyzer, _flow: &HttpFlow) -> bool {
            true
        }
    }

    #[derive(Debug)]
    pub struct HttpRequest;
    impl ExpressionValue<Config> for HttpRequest {
        type Classifier = super::HttpStartLineClassifier;

        const SHOULD_GRANT_BY_FLOW: bool = true;

        fn should_break_grant(&self, packet: &HttpStartLineAnalyzer) -> bool {
            packet.is_response() || packet.is_request()
        }

        fn check(&self, _packet: &HttpStartLineAnalyzer, flow: &HttpFlow) -> bool {
            flow.state == State::Request
        }
    }

    #[derive(Debug)]
    pub struct HttpResponse;
    impl ExpressionValue<Config> for HttpResponse {
        type Classifier = super::HttpStartLineClassifier;

        const SHOULD_GRANT_BY_FLOW: bool = true;

        fn should_break_grant(&self, packet: &HttpStartLineAnalyzer) -> bool {
            packet.is_request() || packet.is_response()
        }

        fn check(&self, _packet: &HttpStartLineAnalyzer, flow: &HttpFlow) -> bool {
            flow.state == State::Response
        }
    }

    pub use super::analyzer::Method as HttpMethod;
    impl ExpressionValue<Config> for HttpMethod {
        type Classifier = super::HttpStartLineClassifier;

        fn check(&self, packet: &HttpStartLineAnalyzer, _flow: &HttpFlow) -> bool {
            Some(*self) == packet.method()
        }
    }

    #[derive(Debug)]
    pub struct HttpCode(pub &'static str);
    impl ExpressionValue<Config> for HttpCode {
        type Classifier = super::HttpStartLineClassifier;

        fn check(&self, packet: &HttpStartLineAnalyzer, _flow: &HttpFlow) -> bool {
            Some(self.0) == packet.code()
        }
    }

    #[derive(Debug)]
    pub struct HttpHeaderName(pub &'static str);
    impl ExpressionValue<Config> for HttpHeaderName {
        type Classifier = super::HttpHeaderClassifier;

        fn check(&self, packet: &HttpHeaderAnalyzer, _flow: &HttpFlow) -> bool {
            packet.find_header(self.0).is_some()
        }
    }

    #[derive(Debug)]
    pub struct HttpHeader(pub &'static str, pub &'static str);
    impl ExpressionValue<Config> for HttpHeader {
        type Classifier = super::HttpHeaderClassifier;

        fn check(&self, packet: &HttpHeaderAnalyzer, _flow: &HttpFlow) -> bool {
            match packet.find_header(self.0) {
                Some(value) => value.contains(self.1),
                None => false,
            }
        }
    }
}
