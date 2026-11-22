use super::xor::xor_inplace;

pub struct VlessXorServer {
    key: Vec<u8>,
}

impl VlessXorServer {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    pub fn decrypt(&self, data: &mut [u8]) {
        xor_inplace(data, &self.key);
    }
}
