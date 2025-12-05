pub fn channel_payload(count: usize) -> Vec<u16> {
    (0..count).map(|i| (i % 256) as u16).collect()
}
