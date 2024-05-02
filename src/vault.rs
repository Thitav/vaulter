use crate::crypto::{self, SALT_LEN};
use ring::aead::chacha20_poly1305_openssh::TAG_LEN;
use std::io::{BufReader, BufWriter, Read, Write};

// IMPROVE THIS CODE, TOO REPETITIVE, OPTIMIZE IF POSSIBLE

pub fn buffer_encrypt(
    buf_in: impl Read,
    buf_out: impl Write,
    key: &[u8],
    size_chunk: usize,
    size_data: usize,
) {
    let mut buf_reader = BufReader::new(buf_in);
    let mut buf_writer = BufWriter::new(buf_out);
    let mut chunk = vec![0u8; size_chunk];

    let salt = crypto::generate_salt().unwrap();
    buf_writer.write(&salt).unwrap();
    let dkey = crypto::derive_key(key, &salt);

    let nchunks = size_data / size_chunk;
    for i in 0..nchunks {
        let mut nonce_sequence = crypto::CounterNonceSequence::new(&salt);
        nonce_sequence.counter = u32::try_from(i).unwrap();

        buf_reader.read(&mut chunk).unwrap();

        let tag = crypto::aead_encrypt(&mut chunk, dkey, nonce_sequence).unwrap();

        buf_writer.write(&chunk).unwrap();
        buf_writer.write(tag.as_ref()).unwrap();
    }

    if size_data % size_chunk != 0 {
        chunk.resize(size_data - (size_chunk * nchunks), 0);
        buf_reader.read(&mut chunk).unwrap();

        let mut nonce_sequence = crypto::CounterNonceSequence::new(&salt);
        nonce_sequence.counter = u32::try_from(nchunks + 1).unwrap();

        let tag = crypto::aead_encrypt(&mut chunk, dkey, nonce_sequence).unwrap();

        buf_writer.write(&chunk).unwrap();
        buf_writer.write(tag.as_ref()).unwrap();
    }

    buf_writer.flush().unwrap();
}

pub fn buffer_decrypt(
    buf_in: impl Read,
    buf_out: impl Write,
    key: &[u8],
    size_chunk: usize,
    size_data: usize,
) {
    let size_chunk = size_chunk + TAG_LEN;
    let size_data = size_data - SALT_LEN;

    let mut buf_reader = BufReader::new(buf_in);
    let mut buf_writer = BufWriter::new(buf_out);
    let mut chunk = vec![0u8; size_chunk];

    let mut salt = crypto::Salt::default();
    buf_reader.read(&mut salt).unwrap();
    let dkey = crypto::derive_key(key, &salt);

    let nchunks = size_data / size_chunk;
    for i in 0..nchunks {
        let mut nonce_sequence = crypto::CounterNonceSequence::new(&salt);
        nonce_sequence.counter = u32::try_from(i).unwrap();

        buf_reader.read(&mut chunk).unwrap();
        let data = crypto::aead_decrypt(&mut chunk, dkey, nonce_sequence).unwrap();

        buf_writer.write(&data).unwrap();
    }

    if size_data % size_chunk != 0 {
        chunk.resize(size_data - (size_chunk * nchunks), 0);

        let mut nonce_sequence = crypto::CounterNonceSequence::new(&salt);
        nonce_sequence.counter = u32::try_from(nchunks + 1).unwrap();

        buf_reader.read(&mut chunk).unwrap();
        let data = crypto::aead_decrypt(&mut chunk, dkey, nonce_sequence).unwrap();

        buf_writer.write(&data).unwrap();
    }

    buf_writer.flush().unwrap();
}
