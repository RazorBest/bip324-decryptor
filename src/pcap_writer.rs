use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::mem;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::{DataLink, PcapResult};
use rtrb::Consumer;
use slapp::tcp_util::tcp_ipv4_session_pair;
use tracing::info;

const DUMPER_MAX_WRITTEN_DEFAULT: usize = 512 * 1024 * 1024; // 512 MB
const PCAP_HEADER_SIZE: usize = 28;

pub fn enhanced_packet_from_payload(
    payload: Vec<u8>,
    timestamp: u64,
) -> EnhancedPacketBlock<'static> {
    EnhancedPacketBlock {
        interface_id: 0,
        // packet.timestamp is actually milliseconds, but it's a bug
        // This was fixed in 3.0.0, but not published on crates.io: https://github.com/courvoif/pcap-file
        timestamp: Duration::from_micros(timestamp),
        original_len: payload.len() as u32,
        data: Cow::from(payload),
        options: vec![],
    }
}

pub type MonotonicCounter = u64;

#[derive(Debug, Clone)]
pub struct PacketRecord {
    pub monocounter: MonotonicCounter,
    pub timestamp: u64,
    pub session_id: u64,
    pub is_client: bool,
    pub header: Vec<u8>,
    pub data: Vec<u8>,
    pub close: bool,
}

#[derive(Debug, Clone)]
pub struct DumperOptions {
    pub path_prefix: String,
}

pub struct Dumper {
    /// The path prefix used to generate files
    pub prefix: Box<str>,
    /// Max written bytes allowed until the file is rotated
    pub max_written: usize,
    /// The underlying pcap writer object
    pub writer: PcapNgWriter<File>,
    /// Amount in bytes written to the file
    pub written: usize,
}

impl Dumper {
    pub fn new(opts: &DumperOptions) -> Self {
        let prefix = &opts.path_prefix;
        let (writer, written) = Self::create_pcapng_writer(prefix);

        Self {
            prefix: prefix.clone().into(),
            max_written: DUMPER_MAX_WRITTEN_DEFAULT,
            writer,
            written,
        }
    }

    fn create_file(prefix: &str) -> std::io::Result<File> {
        let mut index = 0;
        loop {
            let now: DateTime<Utc> = Utc::now();
            let path = if index == 0 {
                format!("{}_{}.pcap", prefix, now.format("%Y%m%d%H%M%S"))
            } else {
                format!(
                    "{}_{}_{:03}.pcap",
                    prefix,
                    now.format("%Y%m%d%H%M%S"),
                    index
                )
            };

            let ret = OpenOptions::new().write(true).create_new(true).open(&path);

            match &ret {
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    index += 1;
                }
                _ => {
                    info!("Created file {}", &path);
                    return ret;
                }
            }
        }
    }

    fn create_pcapng_writer(prefix: &str) -> (PcapNgWriter<File>, usize) {
        let file = Self::create_file(prefix).unwrap();
        let mut writer = PcapNgWriter::new(file).unwrap();
        // From the documentation of new:
        //      Writes this global pcapng header to the file:
        //      Self {
        //          endianness: Endianness::Native,
        //          major_version: 1,
        //          minor_version: 0,
        //          section_length: -1,
        //          options: vec![]
        //      }
        let mut written = PCAP_HEADER_SIZE;

        let interface = InterfaceDescriptionBlock {
            linktype: DataLink::IPV4,
            snaplen: 0xFFFF,
            options: vec![
                // InterfaceDescriptionOption::IfTsResol(6),
            ],
        };
        written += writer.write_pcapng_block(interface).unwrap();

        (writer, written)
    }

    pub fn push(
        &mut self,
        enhanced_packet_block: EnhancedPacketBlock<'static>,
    ) -> PcapResult<usize> {
        let written = self.writer.write_pcapng_block(enhanced_packet_block)?;
        self.written += written;

        if self.written >= self.max_written {
            let (writer, written) = Self::create_pcapng_writer(&self.prefix);
            self.writer = writer;
            self.written = written;
        }

        Ok(written)
    }
}

pub struct PcapWriter {
    pub running: Arc<AtomicBool>,
    pub to_sort: Vec<(EnhancedPacketBlock<'static>, MonotonicCounter)>,
    pub to_dump: Vec<(EnhancedPacketBlock<'static>, MonotonicCounter)>,
    pub dumper: Dumper,
    pub packet_consumer: Consumer<(EnhancedPacketBlock<'static>, MonotonicCounter)>,
    pub last_update: SystemTime,
}

impl PcapWriter {
    pub fn new(
        running: Arc<AtomicBool>,
        dumper: Dumper,
        packet_consumer: Consumer<(EnhancedPacketBlock<'static>, MonotonicCounter)>,
    ) -> Self {
        Self {
            running,
            to_sort: vec![],
            to_dump: vec![],
            dumper,
            packet_consumer,
            last_update: SystemTime::now(),
        }
    }

    pub fn run(&mut self) {
        loop {
            thread::sleep(Duration::from_millis(100));

            while let Ok((packet, monocounter)) = self.packet_consumer.pop() {
                let (mut src, mut dst) = tcp_ipv4_session_pair(&packet.data);
                if src > dst {
                    mem::swap(&mut src, &mut dst);
                }

                self.to_sort.push((packet, monocounter));
            }

            // Error might happen because of drift
            // But we don't expect big drifts
            // So, even then, the time would eventually pass the threshold
            let Ok(elapsed) = self.last_update.elapsed() else {
                continue;
            };

            if elapsed < Duration::from_millis(800) {
                continue;
            }

            self.last_update = SystemTime::now();

            self.step();

            // Requirement: the producer must not produce after running is set to false
            if !self.running.load(Ordering::SeqCst) && self.to_dump.is_empty() {
                return;
            }
        }
    }

    fn step(&mut self) {
        // Move lost packets from to_sort to to_dump
        // With the condition to not change the last packet in to_dump
        if let Some(last) = self.to_dump.pop() {
            self.to_sort = self
                .to_sort
                .drain(..)
                .filter_map(|packet| {
                    if packet.1 < last.1 {
                        self.to_dump.push(packet);
                        None
                    } else {
                        Some(packet)
                    }
                })
                .collect();

            self.to_dump.push(last);

            self.to_dump.sort_by_key(|(_, monocounter)| *monocounter);
        }

        // Drain to_dump
        for (packet, _) in self.to_dump.drain(..) {
            self.dumper.push(packet).unwrap();
        }

        // Sort the next batch and prepare it for dumping at the next iteration
        self.to_sort.sort_by_key(|(_, monocounter)| *monocounter);
        mem::swap(&mut self.to_dump, &mut self.to_sort);
    }
}
