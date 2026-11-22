pub fn xorfwd(x: &mut [u8]) {
    for i in 4..x.len() {
        x[i] ^= x[i - 4];
    }
}

pub fn xorbkd(x: &mut [u8]) {
    for i in (4..x.len()).rev() {
        x[i] ^= x[i - 4];
    }
}
