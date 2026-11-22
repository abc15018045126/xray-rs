#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    Timeout,
    ConnectionRefused,
    TlsHandshakeFailed,
    DnsLookupFailed,
    Unknown,
}

pub fn explain_error(err_str: &str) -> (&'static str, ErrorCategory) {
    let l = err_str.to_lowercase();
    let has = |ks: &[&str]| ks.iter().any(|k| l.contains(k));
    if has(&["timeout", "timed out", "deadline"]) { ("Request timeout / packet dropped", ErrorCategory::Timeout) }
    else if has(&["connection refused", "10061", "reset by peer"]) { ("Remote endpoint refused connection", ErrorCategory::ConnectionRefused) }
    else if has(&["tls", "handshake", "certificate"]) { ("TLS handshake or SNI interception failure", ErrorCategory::TlsHandshakeFailed) }
    else if has(&["dns", "not resolved", "lookup"]) { ("DNS resolution failure", ErrorCategory::DnsLookupFailed) }
    else { ("General network dispatch error", ErrorCategory::Unknown) }
}

#[derive(Default, Debug, Clone)]
pub struct ErrorCollector {
    errors: Vec<String>,
}

impl ErrorCollector {
    pub fn new() -> Self { Self { errors: Vec::new() } }
    pub fn submit_error(&mut self, err: impl ToString) { self.errors.push(err.to_string()); }
    pub fn underlying_error(&self) -> Option<&str> { self.errors.last().map(|s| s.as_str()) }
    pub fn has_errors(&self) -> bool { !self.errors.is_empty() }
    pub fn count(&self) -> usize { self.errors.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_error_collector() {
        let mut collector = ErrorCollector::new();
        assert!(!collector.has_errors());
        assert_eq!(collector.underlying_error(), None);
        collector.submit_error("first io error");
        collector.submit_error("connection reset by peer");
        assert!(collector.has_errors());
        assert_eq!(collector.count(), 2);
        assert_eq!(collector.underlying_error(), Some("connection reset by peer"));
        let (exp, cat) = explain_error(collector.underlying_error().unwrap());
        assert_eq!(cat, ErrorCategory::ConnectionRefused);
        assert!(exp.contains("refused connection"));
    }
}
