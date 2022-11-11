// Xor Decrypt incoming data stream

pub fn decrypt_strem(buf: &mut Vec<u8>) {
    let key: Vec<u8> = vec![97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107]; //"abcdefghijk".as_bytes();
    let mut i = 0;

    for x in buf.iter_mut() {
        *x = *x ^ key[i % key.len()];
        i = i + 1;
    }
}
