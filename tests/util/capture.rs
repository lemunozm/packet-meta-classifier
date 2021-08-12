use pcap_file::{pcap::PcapReader, DataLink};
use std::fs::File;

pub struct Packet {
    //TODO: timestamp
    pub id: usize,
    pub data: Vec<u8>,
}

pub struct Capture {
    ip_packets: Vec<Packet>,
}

impl Capture {
    pub fn open(file_name: &str) -> Capture {
        let pcap_file = File::open(file_name).expect("Error opening file");
        let pcap_reader = PcapReader::new(pcap_file).unwrap();
        let start = match pcap_reader.header.datalink {
            DataLink::ETHERNET => 14,
            DataLink::LINUX_SLL => 16,
            _ => panic!(
                "Unsupported datalink type {:?} of this capture",
                pcap_reader.header.datalink
            ),
        };

        let mut next_id = 0;
        let ip_packets = pcap_reader
            .map(|pcap| {
                next_id += 1;
                Packet {
                    id: next_id,
                    data: Vec::from(&pcap.unwrap().data[start..]),
                }
            })
            .collect();

        Capture { ip_packets }
    }

    pub fn len(&self) -> usize {
        self.ip_packets.len()
    }

    pub fn iter(&self) -> CaptureIterator {
        self.iter_section(1, self.ip_packets.len())
    }

    pub fn iter_section(&self, from_id: usize, to_id: usize) -> CaptureIterator {
        assert!(from_id > 0, "The first packet must be higher than one");
        assert!(
            to_id <= self.ip_packets.len(),
            "The last packet must not exceed the length or the capture"
        );

        CaptureIterator {
            capture: &self,
            next: from_id - 1,
            max_index: to_id,
        }
    }
}

pub struct CaptureIterator<'a> {
    capture: &'a Capture,
    next: usize,
    max_index: usize,
}

impl<'a> Iterator for CaptureIterator<'a> {
    type Item = &'a Packet;

    fn next(&mut self) -> Option<Self::Item> {
        self.next += 1;
        if self.next <= self.max_index {
            Some(&self.capture.ip_packets[self.next - 1])
        } else {
            None
        }
    }
}
