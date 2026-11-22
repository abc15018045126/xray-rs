#[cfg(test)]
mod tests {
    use super::super::io::KcpIoQueue;

    #[test]
    fn test_kcp_io_queue() {
        let mut queue = KcpIoQueue::new();
        queue.push(b"pkt1".to_vec());
        queue.push(b"pkt2".to_vec());

        assert_eq!(queue.pop(), Some(b"pkt1".to_vec()));
        assert_eq!(queue.pop(), Some(b"pkt2".to_vec()));
    }
}
