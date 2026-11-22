pub use super::config_pb::Config;
use super::conn::FragmentConn;
use crate::common::errors::Result;
use crate::common::net::BoxStream;

impl Config {
    pub fn tcp(&self) {}
    pub fn wrap_conn_client(&self, raw: BoxStream) -> Result<FragmentConn> {
        Ok(FragmentConn::new_client(self.clone(), raw))
    }
    pub fn wrap_conn_server(&self, raw: BoxStream) -> Result<FragmentConn> {
        Ok(FragmentConn::new_server(self.clone(), raw))
    }
    pub fn length_for_segment(&self, seg_idx: usize) -> (i64, i64) {
        if !self.lengths_min.is_empty() && !self.lengths_max.is_empty() {
            let i = seg_idx.min(self.lengths_min.len() - 1);
            (self.lengths_min[i], self.lengths_max[i.min(self.lengths_max.len() - 1)])
        } else {
            (self.length_min, self.length_max)
        }
    }
    pub fn delay_for_segment(&self, seg_idx: usize) -> (i64, i64) {
        if !self.delays_min.is_empty() && !self.delays_max.is_empty() {
            let i = seg_idx.min(self.delays_min.len() - 1);
            (self.delays_min[i], self.delays_max[i.min(self.delays_max.len() - 1)])
        } else {
            (self.delay_min, self.delay_max)
        }
    }
    pub fn merge_tls_hello_segments(&self) -> bool {
        if !self.delays_max.is_empty() {
            self.delays_max.len() == 1 && self.delays_max[0] == 0
        } else {
            self.delay_max == 0
        }
    }
}
