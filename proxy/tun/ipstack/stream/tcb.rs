use super::seqnum::SeqNum;
use etherparse::TcpHeader;
use std::{collections::BTreeMap, time::Duration};

pub(super) const MAX_UNACK: u32 = u16::MAX as u32;
pub(super) const READ_BUFFER_SIZE: usize = u16::MAX as usize;
pub(super) const MAX_COUNT_FOR_DUP_ACK: usize = 3;

pub(super) const RTO: std::time::Duration = std::time::Duration::from_secs(1);

pub(super) const MAX_RETRANSMIT_COUNT: usize = 3;

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum TcpState {
    Listen,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    TimeWait,
    CloseWait,
    LastAck,
    Closed,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub(super) enum PacketType {
    WindowUpdate,
    Invalid,
    RetransmissionRequest,
    NewPacket,
    Ack,
    KeepAlive,
}

#[derive(Debug, Clone)]
pub(crate) struct Tcb {
    seq: SeqNum,
    ack: SeqNum,
    mtu: u16,
    last_received_ack: SeqNum,
    send_window: u16,
    state: TcpState,
    inflight_packets: BTreeMap<SeqNum, InflightPacket>,
    unordered_packets: BTreeMap<SeqNum, Vec<u8>>,
    duplicate_ack_count: usize,
    duplicate_ack_count_helper: SeqNum,
    max_unacked_bytes: u32,
    read_buffer_size: usize,
    queued_read_bytes: usize,
    last_advertised_window: u16,
    max_count_for_dup_ack: usize,
    rto: std::time::Duration,
    max_retransmit_count: usize,
}

impl Tcb {
    pub(super) fn new(
        ack: SeqNum,
        mtu: u16,
        max_unacked_bytes: u32,
        read_buffer_size: usize,
        max_count_for_dup_ack: usize,
        rto: std::time::Duration,
        max_retransmit_count: usize,
    ) -> Tcb {
        #[cfg(debug_assertions)]
        let seq = 100;
        #[cfg(not(debug_assertions))]
        let seq: u32 = rand::random();
        Tcb {
            seq: seq.into(),
            ack,
            mtu,
            last_received_ack: seq.into(),
            send_window: u16::MAX,
            state: TcpState::Listen,
            inflight_packets: BTreeMap::new(),
            unordered_packets: BTreeMap::new(),
            duplicate_ack_count: 0,
            duplicate_ack_count_helper: seq.into(),
            max_unacked_bytes,
            read_buffer_size,
            queued_read_bytes: 0,
            last_advertised_window: read_buffer_size.min(u16::MAX as usize) as u16,
            max_count_for_dup_ack,
            rto,
            max_retransmit_count,
        }
    }

    pub fn calculate_payload_max_len(&self, ip_header_size: usize, tcp_header_size: usize) -> usize {
        let send_window = self.get_send_window() as usize;
        let mtu = self.get_mtu() as usize;
        std::cmp::min(send_window, mtu.saturating_sub(ip_header_size + tcp_header_size))
    }

    pub fn update_duplicate_ack_count(&mut self, rcvd_ack: SeqNum) {
        if rcvd_ack == self.duplicate_ack_count_helper && rcvd_ack < self.seq {
            self.duplicate_ack_count = self.duplicate_ack_count.saturating_add(1);
        } else {
            self.duplicate_ack_count_helper = rcvd_ack;
            self.duplicate_ack_count = 0;
        }
    }

    pub fn is_duplicate_ack_count_exceeded(&self) -> bool {
        self.duplicate_ack_count >= self.max_count_for_dup_ack
    }

    pub(super) fn add_unordered_packet(&mut self, mut seq: SeqNum, mut buf: Vec<u8>) {
        if seq < self.ack {
            let overlap = self.ack.distance(seq) as usize;
            if overlap >= buf.len() {
                #[rustfmt::skip]
                log::trace!("{:?}: Received duplicate packet seq {seq} < self ack {}, len = {}", self.state, self.ack, buf.len());
                return;
            }
            buf.drain(..overlap);
            seq = self.ack;
        }
        let room = self.remaining_queue_room();
        let offset = seq.distance(self.ack) as usize;
        if offset >= room {
            return;
        }
        let max_len = room - offset;
        if buf.len() > max_len {
            buf.truncate(max_len);
        }
        if !buf.is_empty() {
            self.unordered_packets.insert(seq, buf);
        }
    }
    pub(super) fn remaining_queue_room(&self) -> usize {
        self.read_buffer_size.saturating_sub(self.queued_read_bytes)
    }
    pub(super) fn on_data_queued(&mut self, len: usize) {
        self.queued_read_bytes = self.queued_read_bytes.saturating_add(len);
    }
    pub(super) fn on_data_consumed(&mut self, len: usize) {
        self.queued_read_bytes = self.queued_read_bytes.saturating_sub(len);
    }
    pub(super) fn set_last_advertised_window(&mut self, win: u16) {
        self.last_advertised_window = win;
    }
    pub(super) fn should_send_window_update(&self) -> bool {
        if self.state != TcpState::Established {
            return false;
        }
        let cur = self.get_recv_window();
        let half = (self.read_buffer_size / 2).min(u16::MAX as usize) as u16;
        (self.last_advertised_window == 0 && cur >= self.mtu.min(half))
            || (self.last_advertised_window < half && cur >= half)
    }
    pub(super) fn get_available_read_buffer_size(&self) -> usize {
        let used = self.get_unordered_packets_total_len().saturating_add(self.queued_read_bytes);
        self.read_buffer_size.saturating_sub(used)
    }
    #[inline]
    pub(crate) fn get_unordered_packets_total_len(&self) -> usize {
        self.unordered_packets.values().map(|p| p.len()).sum()
    }

    pub(super) fn consume_unordered_packets(&mut self, max_bytes: usize) -> Option<Vec<u8>> {
        let mut data = Vec::new();
        let mut remaining_bytes = max_bytes;

        while remaining_bytes > 0 {
            if let Some(seq) = self.unordered_packets.keys().next().copied() {
                if seq != self.ack {
                    break;
                }

                let mut payload = self.unordered_packets.remove(&seq).unwrap();
                let payload_len = payload.len();

                if payload_len <= remaining_bytes {
                    data.extend(payload);
                    self.ack += payload_len as u32;
                    remaining_bytes -= payload_len;
                } else {
                    let remaining_payload = payload.split_off(remaining_bytes);
                    data.extend_from_slice(&payload);
                    self.ack += remaining_bytes as u32;
                    self.unordered_packets.insert(self.ack, remaining_payload);
                    break;
                }
            } else {
                break;
            }
        }

        if data.is_empty() { None } else { Some(data) }
    }

    pub(super) fn increase_seq(&mut self) {
        self.seq += 1;
    }
    pub(super) fn get_seq(&self) -> SeqNum {
        self.seq
    }
    pub(super) fn increase_ack(&mut self) {
        self.ack += 1;
    }
    pub(super) fn get_ack(&self) -> SeqNum {
        self.ack
    }
    pub(super) fn get_mtu(&self) -> u16 {
        self.mtu
    }
    pub(super) fn get_last_received_ack(&self) -> SeqNum {
        self.last_received_ack
    }
    pub(super) fn change_state(&mut self, state: TcpState) {
        self.state = state;
    }
    pub(super) fn get_state(&self) -> TcpState {
        self.state
    }
    pub(super) fn update_send_window(&mut self, window: u16) {
        self.send_window = window;
    }
    pub(super) fn get_send_window(&self) -> u16 {
        self.send_window
    }
    pub(super) fn get_recv_window(&self) -> u16 {
        self.get_available_read_buffer_size().try_into().unwrap_or(u16::MAX)
    }

    pub(super) fn check_pkt_type(&self, tcp_header: &TcpHeader, payload: &[u8]) -> PacketType {
        let rcvd_ack = SeqNum(tcp_header.acknowledgment_number);
        let rcvd_seq = SeqNum(tcp_header.sequence_number);
        let rcvd_window = tcp_header.window_size;
        let len = payload.len();
        let res = if rcvd_ack > self.seq {
            PacketType::Invalid
        } else {
            match rcvd_ack.cmp(&self.get_last_received_ack()) {
                std::cmp::Ordering::Less => PacketType::Invalid,
                std::cmp::Ordering::Equal => {
                    if self.ack - 1 == rcvd_seq && payload.len() <= 1 {
                        PacketType::KeepAlive
                    } else if !payload.is_empty() {
                        PacketType::NewPacket
                    } else if self.get_send_window() == rcvd_window && self.seq != rcvd_ack && self.is_duplicate_ack_count_exceeded() {
                        PacketType::RetransmissionRequest
                    } else {
                        PacketType::WindowUpdate
                    }
                }
                std::cmp::Ordering::Greater => {
                    if payload.is_empty() {
                        PacketType::Ack
                    } else {
                        PacketType::NewPacket
                    }
                }
            }
        };
        #[rustfmt::skip]
        log::trace!("received {{ ack = {:08X?}, seq = {:08X?}, window = {rcvd_window} }}, self {{ ack = {:08X?}, seq = {:08X?}, send_window = {} }}, len = {len}, {res:?}", rcvd_ack.0, rcvd_seq.0, self.ack.0, self.seq.0, self.get_send_window());
        res
    }

    pub(super) fn add_inflight_packet(&mut self, buf: Vec<u8>) -> std::io::Result<()> {
        if buf.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Empty payload"));
        }
        let buf_len = buf.len() as u32;
        self.inflight_packets.insert(self.seq, InflightPacket::new(self.seq, buf, self.rto));
        self.seq += buf_len;
        Ok(())
    }

    pub(super) fn update_last_received_ack(&mut self, ack: SeqNum) {
        self.last_received_ack = ack;
    }

    pub(crate) fn update_inflight_packet_queue(&mut self, ack: SeqNum) {
        match self.inflight_packets.first_key_value() {
            None => return,
            Some((&seq, _)) if ack < seq => return,
            _ => {}
        }
        if let Some(seq) = self
            .inflight_packets
            .iter()
            .find(|(_, p)| p.contains_seq_num(ack - 1))
            .map(|(&s, _)| s)
        {
            let mut inflight_packet = self.inflight_packets.remove(&seq).unwrap();
            let distance = ack.distance(inflight_packet.seq) as usize;
            if distance < inflight_packet.payload.len() {
                inflight_packet.payload.drain(0..distance);
                inflight_packet.seq = ack;
                self.inflight_packets.insert(ack, inflight_packet);
            }
        }
        self.inflight_packets.retain(|_, p| ack < p.seq + p.payload.len() as u32);
    }

    pub(crate) fn find_inflight_packet(&self, seq: SeqNum) -> Option<&InflightPacket> {
        self.inflight_packets.get(&seq)
    }

    #[must_use]
    pub(crate) fn collect_timed_out_inflight_packets(&mut self) -> Vec<InflightPacket> {
        let mut retransmit_list = Vec::new();

        self.inflight_packets.retain(|_, packet| {
            if packet.retransmit_count >= self.max_retransmit_count {
                log::warn!("Packet with seq {:?} reached max retransmit count, dropping packet", packet.seq);
                return false;
            }
            if packet.is_timed_out() {
                packet.retransmit_count += 1;
                packet.retransmit_timeout *= 2;
                packet.send_time = std::time::Instant::now();
                retransmit_list.push(packet.clone());
            }
            true
        });
        retransmit_list
    }

    pub(crate) fn get_inflight_packets_total_len(&self) -> usize {
        self.inflight_packets.values().map(|p| p.payload.len()).sum()
    }

    #[allow(dead_code)]
    pub(crate) fn get_all_inflight_packets(&self) -> Vec<&InflightPacket> {
        self.inflight_packets.values().collect::<Vec<_>>()
    }

    pub fn is_send_buffer_full(&self) -> bool {
        self.seq.distance(self.get_last_received_ack()) >= self.max_unacked_bytes.min(self.get_send_window() as u32)
    }
}

#[derive(Debug, Clone)]
pub struct InflightPacket {
    pub seq: SeqNum,
    pub payload: Vec<u8>,
    pub send_time: std::time::Instant,
    pub retransmit_count: usize,
    pub retransmit_timeout: std::time::Duration,
}

impl InflightPacket {
    fn new(seq: SeqNum, payload: Vec<u8>, rto: Duration) -> Self {
        Self {
            seq,
            payload,
            send_time: std::time::Instant::now(),
            retransmit_count: 0,
            retransmit_timeout: rto,
        }
    }
    pub(crate) fn contains_seq_num(&self, seq: SeqNum) -> bool {
        self.seq <= seq && seq < self.seq + self.payload.len() as u32
    }
    pub(crate) fn is_timed_out(&self) -> bool {
        self.send_time.elapsed() >= self.retransmit_timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_flight_packet() {
        let p = InflightPacket::new((u32::MAX - 1).into(), vec![10, 20, 30, 40, 50], RTO);

        assert!(p.contains_seq_num((u32::MAX - 1).into()));
        assert!(p.contains_seq_num(u32::MAX.into()));
        assert!(p.contains_seq_num(0.into()));
        assert!(p.contains_seq_num(1.into()));
        assert!(p.contains_seq_num(2.into()));

        assert!(!p.contains_seq_num(3.into()));
    }

    #[test]
    fn test_get_unordered_packets_with_max_bytes() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            RTO,
            MAX_RETRANSMIT_COUNT,
        );

        tcb.add_unordered_packet(SeqNum(1000), vec![1; 500]);
        tcb.add_unordered_packet(SeqNum(1500), vec![2; 500]);
        tcb.add_unordered_packet(SeqNum(2000), vec![3; 500]);

        let data = tcb.consume_unordered_packets(700).unwrap();
        assert_eq!(data.len(), 700);
        assert_eq!(data[..500], vec![1; 500]);
        assert_eq!(data[500..700], vec![2; 200]);
        assert_eq!(tcb.ack, SeqNum(1700));
        assert_eq!(tcb.unordered_packets.len(), 2);
        assert_eq!(tcb.unordered_packets.get(&SeqNum(1700)).unwrap().len(), 300);
        assert_eq!(tcb.unordered_packets.get(&SeqNum(2000)).unwrap().len(), 500);

        let data = tcb.consume_unordered_packets(800).unwrap();
        assert_eq!(data.len(), 800);
        assert_eq!(data[..300], vec![2; 300]);
        assert_eq!(data[300..800], vec![3; 500]);
        assert_eq!(tcb.ack, SeqNum(2500));
        assert_eq!(tcb.unordered_packets.len(), 0);

        let data = tcb.consume_unordered_packets(1000);
        assert!(data.is_none());
    }

    #[test]
    fn test_update_inflight_packet_queue() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            RTO,
            MAX_RETRANSMIT_COUNT,
        );
        tcb.seq = SeqNum(100);

        tcb.add_inflight_packet(vec![1; 500]).unwrap();
        tcb.add_inflight_packet(vec![2; 500]).unwrap();
        tcb.add_inflight_packet(vec![3; 500]).unwrap();

        tcb.update_inflight_packet_queue(SeqNum(800));
        assert_eq!(tcb.inflight_packets.len(), 2);
        let first_packet = tcb.inflight_packets.first_key_value().unwrap().1;
        assert_eq!(first_packet.seq, SeqNum(800));
        assert_eq!(first_packet.payload.len(), 300);
        let second_packet = tcb.inflight_packets.last_key_value().unwrap().1;
        assert_eq!(second_packet.seq, SeqNum(1100));

        tcb.update_inflight_packet_queue(SeqNum(2000));
        assert_eq!(tcb.inflight_packets.len(), 0);
    }

    #[test]
    fn test_update_inflight_packet_queue_cumulative_ack() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            RTO,
            MAX_RETRANSMIT_COUNT,
        );
        tcb.seq = SeqNum(1000);

        tcb.add_inflight_packet(vec![1; 500]).unwrap();
        tcb.add_inflight_packet(vec![2; 500]).unwrap();
        tcb.add_inflight_packet(vec![3; 500]).unwrap();

        tcb.update_inflight_packet_queue(SeqNum(2500));
        assert_eq!(tcb.inflight_packets.len(), 0);
    }

    #[test]
    fn test_retransmit_with_exponential_backoff() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            RTO,
            MAX_RETRANSMIT_COUNT,
        );

        tcb.add_inflight_packet(vec![1; 500]).unwrap();

        for i in 0..MAX_RETRANSMIT_COUNT {
            let timeout = tcb.inflight_packets.values().next().unwrap().retransmit_timeout + std::time::Duration::from_millis(100);
            println!("timeout: {timeout:?}");
            std::thread::sleep(timeout);

            let packets = tcb.collect_timed_out_inflight_packets();
            assert_eq!(packets.len(), 1);
            let packet = &packets[0];
            assert_eq!(packet.retransmit_count, i + 1);
            assert!(packet.retransmit_timeout > RTO);
        }

        let packets = tcb.collect_timed_out_inflight_packets();
        assert!(packets.is_empty());
        assert!(tcb.inflight_packets.is_empty());
    }

    #[test]
    fn test_recv_window_zero_backpressure_and_reopen() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            4096,
            MAX_COUNT_FOR_DUP_ACK,
            RTO,
            MAX_RETRANSMIT_COUNT,
        );
        tcb.change_state(TcpState::Established);
        assert_eq!(tcb.get_recv_window(), 4096);

        // Enqueue 4096 bytes -> advertised window drops to 0.
        tcb.add_unordered_packet(SeqNum(1000), vec![0xaa; 4096]);
        let consumed = tcb.consume_unordered_packets(4096).unwrap();
        assert_eq!(consumed.len(), 4096);
        tcb.on_data_queued(consumed.len());
        assert_eq!(tcb.get_recv_window(), 0);
        tcb.set_last_advertised_window(0);

        // Packet arriving while window is 0 must not be buffered or advance ack.
        tcb.add_unordered_packet(SeqNum(5096), vec![0xbb; 500]);
        assert!(tcb.consume_unordered_packets(500).is_none());
        assert_eq!(tcb.get_ack(), SeqNum(5096));

        // Reader drains 2048 bytes -> window reopens and triggers window update ACK.
        tcb.on_data_consumed(2048);
        assert_eq!(tcb.get_recv_window(), 2048);
        assert!(tcb.should_send_window_update());
        tcb.set_last_advertised_window(2048);
        assert!(!tcb.should_send_window_update());
    }
}
