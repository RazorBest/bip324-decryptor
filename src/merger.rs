use std::collections::{HashMap, VecDeque};
use std::mem;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;

use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use rtrb::{Consumer, Producer};
use slapp::tcp_util::{tcp_ipv4_seq, tcp_ipv4_syn};
use slapp::util::{CircularSeqBuffer, update_checksum_ipv4_tcp_packet};
use tracing::debug;

use crate::pcap_writer::{MonotonicCounter, PacketRecord, enhanced_packet_from_payload};
use crate::util::producer_blocking_push;

const PLAINTEXT_BUFFER_SIZE: usize = 65535 * 16;

pub struct SessionInfo {
    pending: VecDeque<PacketRecord>,
    plaintext_ring: Option<CircularSeqBuffer>,
    plaintext_seq_initialized: bool,
}

impl SessionInfo {
    fn new() -> Self {
        Self {
            pending: VecDeque::new(),
            plaintext_ring: None,
            plaintext_seq_initialized: false,
        }
    }

    fn allocate_buffer_if_none(&mut self, buffer_size: usize) -> &mut CircularSeqBuffer {
        if self.plaintext_ring.is_none() {
            self.plaintext_ring = Some(CircularSeqBuffer::new(buffer_size));
        }

        self.plaintext_ring.as_mut().unwrap()
    }
}

pub struct CloseFlags {
    closed_session_packet: bool,
    closed_session_plaintext: bool,
}

impl CloseFlags {
    fn new() -> Self {
        Self {
            closed_session_packet: false,
            closed_session_plaintext: false,
        }
    }

    fn closed(&self) -> bool {
        self.closed_session_packet && self.closed_session_plaintext
    }
}

#[derive(Clone)]
pub struct PlaintextRecord {
    pub session_id: u64,
    pub is_client: bool,
    pub counter: i64,
    pub data: Vec<u8>,
    pub close: bool,
}

pub struct MergerLogger {
    pub running: Arc<AtomicBool>,
    pub plaintext_consumer: Consumer<PlaintextRecord>,
    pub packet_consumer: Consumer<PacketRecord>,
    pub session_map: HashMap<(u64, bool), SessionInfo>,
    pub close_tracker: HashMap<(u64, bool), CloseFlags>,
    pub encrypted_producer: Producer<(EnhancedPacketBlock<'static>, MonotonicCounter)>,
    pub plaintext_producer: Producer<(EnhancedPacketBlock<'static>, MonotonicCounter)>,
}

impl MergerLogger {
    pub fn run(&mut self) {
        loop {
            if !self.running.load(Ordering::SeqCst) {
                return;
            }

            while let Ok(plaintext_record) = self.plaintext_consumer.pop() {
                self.on_plaintext_record(plaintext_record);

                if !self.running.load(Ordering::SeqCst) {
                    return;
                }
            }

            while let Ok(packet) = self.packet_consumer.pop() {
                self.on_tcp_packet_template(packet);

                if !self.running.load(Ordering::SeqCst) {
                    return;
                }
            }

            thread::sleep(Duration::from_millis(100));
        }
    }

    fn on_plaintext_record(&mut self, plaintext_record: PlaintextRecord) {
        let PlaintextRecord {
            session_id,
            is_client,
            counter: seq,
            data,
            close,
        } = plaintext_record;

        if close {
            let cflags = self
                .close_tracker
                .entry((session_id, is_client))
                .or_insert_with(|| CloseFlags::new());
            cflags.closed_session_plaintext = true;

            if cflags.closed() {
                let _ = self.session_map.remove(&(session_id, is_client));
                let _ = self.close_tracker.remove(&(session_id, is_client));
                debug!(
                    "Remove session info plaintext: {}, {}",
                    session_id, is_client
                );
            }
            return;
        }

        let sess = self
            .session_map
            .entry((session_id, is_client))
            .or_insert_with(|| {
                debug!(
                    "Create session info plaintext: {}, {}",
                    session_id, is_client
                );
                SessionInfo::new()
            });

        let _ = sess.allocate_buffer_if_none(PLAINTEXT_BUFFER_SIZE);
        let plaintext_ring = sess.plaintext_ring.as_mut().unwrap();

        if !sess.plaintext_seq_initialized {
            sess.plaintext_seq_initialized = true;
            plaintext_ring.seq = seq as u32;
        }

        plaintext_ring.push_data_overwrite(&data);

        let mut pending = mem::take(&mut sess.pending);
        pending.retain(|packet| {
            let resolved = Self::try_resolve_payload_from_buffer(
                sess,
                &mut self.encrypted_producer,
                &mut self.plaintext_producer,
                packet,
            );

            !resolved
        });
        sess.pending = pending;
    }

    fn on_tcp_packet_template(&mut self, packet: PacketRecord) {
        if packet.close {
            let cflags = self
                .close_tracker
                .entry((packet.session_id, packet.is_client))
                .or_insert_with(|| CloseFlags::new());
            cflags.closed_session_packet = true;

            if cflags.closed() {
                let _ = self
                    .session_map
                    .remove(&(packet.session_id, packet.is_client));
                let _ = self
                    .close_tracker
                    .remove(&(packet.session_id, packet.is_client));
                debug!(
                    "Remove session info packet: {}, {}",
                    packet.session_id, packet.is_client
                );
            }
            return;
        }

        let sess = self
            .session_map
            .entry((packet.session_id, packet.is_client))
            .or_insert_with(|| {
                debug!(
                    "Create session info packet: {}, {}",
                    packet.session_id, packet.is_client
                );
                SessionInfo::new()
            });
        if !Self::try_resolve_payload_from_buffer(
            sess,
            &mut self.encrypted_producer,
            &mut self.plaintext_producer,
            &packet,
        ) {
            sess.pending.push_back(packet);
        }
    }

    fn do_resolve_payload_from_buffer(
        session: &mut SessionInfo,
        encrypted_producer: &mut Producer<(EnhancedPacketBlock<'static>, MonotonicCounter)>,
        plaintext_producer: &mut Producer<(EnhancedPacketBlock<'static>, MonotonicCounter)>,
        packet: &PacketRecord,
    ) {
        let seq = tcp_ipv4_seq(&packet.header);

        let mut data_ptxt = packet.data.to_vec();
        if !data_ptxt.is_empty() {
            let plaintext_ring = session.allocate_buffer_if_none(PLAINTEXT_BUFFER_SIZE);
            plaintext_ring.write_from_buffer_to_slice(&mut data_ptxt, seq);
        }

        let payload_enc: Vec<u8> = packet.header.iter().chain(&packet.data).copied().collect();
        let mut payload_ptxt: Vec<u8> = packet.header.iter().copied().chain(data_ptxt).collect();

        update_checksum_ipv4_tcp_packet(&mut payload_ptxt);

        let packet_enc = enhanced_packet_from_payload(payload_enc, packet.timestamp);
        let packet_ptxt = enhanced_packet_from_payload(payload_ptxt, packet.timestamp);

        producer_blocking_push(encrypted_producer, (packet_enc, packet.monocounter));
        producer_blocking_push(plaintext_producer, (packet_ptxt, packet.monocounter));
    }

    fn try_resolve_payload_from_buffer(
        session: &mut SessionInfo,
        encrypted_producer: &mut Producer<(EnhancedPacketBlock<'static>, MonotonicCounter)>,
        plaintext_producer: &mut Producer<(EnhancedPacketBlock<'static>, MonotonicCounter)>,
        packet: &PacketRecord,
    ) -> bool {
        if tcp_ipv4_syn(&packet.header) || packet.data.is_empty() {
            Self::do_resolve_payload_from_buffer(
                session,
                encrypted_producer,
                plaintext_producer,
                packet,
            );
            return true;
        }

        let seq = tcp_ipv4_seq(&packet.header);
        let end_seq = seq.wrapping_add(packet.data.len() as u32).wrapping_sub(1);
        let rb = session.allocate_buffer_if_none(PLAINTEXT_BUFFER_SIZE);
        if !rb.seq_in_buf(seq) || !rb.seq_in_buf(end_seq) {
            return false;
        }

        Self::do_resolve_payload_from_buffer(
            session,
            encrypted_producer,
            plaintext_producer,
            packet,
        );

        true
    }
}
