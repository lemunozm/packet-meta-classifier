use arrayref::array_ref;

use gpc_testing::capture::{Capture, CaptureIterator, CapturedPacket};
use pcap_file::{pcap::PcapReader, DataLink};

use std::fs::File;

pub struct IpCapture {
    ip_packets: Vec<CapturedPacket>,
}

impl IpCapture {
    pub fn open(file_name: &str) -> Self {
        let pcap_file = File::open(file_name).expect("Error opening file");
        let pcap_reader = PcapReader::new(pcap_file).unwrap();
        let datalink = pcap_reader.header.datalink;
        let start = match datalink {
            DataLink::ETHERNET => 14,
            DataLink::LINUX_SLL => 16,
            _ => unimplemented!(
                "Unsupported datalink type {:?} of this capture",
                pcap_reader.header.datalink
            ),
        };

        let mut next_id = 0;
        let ip_packets = pcap_reader
            .map(|pcap| {
                let pcap = pcap.unwrap();
                next_id += 1;
                CapturedPacket {
                    id: next_id,
                    uplink: match datalink {
                        DataLink::ETHERNET => todo!(),
                        DataLink::LINUX_SLL => {
                            let value = u16::from_be_bytes(*array_ref![pcap.data, 0, 2]);
                            match value {
                                4 => true,
                                0 => false,
                                _ => unimplemented!("{}", value),
                            }
                        }
                        _ => unimplemented!(),
                    },
                    data: Vec::from(&pcap.data[start..]),
                }
            })
            .collect();

        Self { ip_packets }
    }
}

impl Capture for IpCapture {
    fn len(&self) -> usize {
        self.ip_packets.len()
    }

    fn section(&self, from_id: usize, to_id: usize) -> CaptureIterator {
        assert!(from_id > 0, "The first packet must be higher than one");
        assert!(
            to_id <= self.ip_packets.len(),
            "The last packet must not exceed the length or the capture"
        );

        CaptureIterator::new(&self.ip_packets[(from_id - 1)..to_id])
    }
}
