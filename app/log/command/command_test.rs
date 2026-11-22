#[cfg(test)]
mod tests {
    use super::super::command::LoggerServer;

    #[test]
    fn test_logger_server_restart() {
        let server = LoggerServer::new();
        assert!(!server.is_restarted());
        assert!(server.restart_logger());
        assert!(server.is_restarted());
    }
}
