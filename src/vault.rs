use crate::crypto::{self};
use ring::aead::chacha20_poly1305_openssh::TAG_LEN;
use std::io::{BufReader, BufWriter, Read, Write};

pub fn buffer_encrypt(buf_in: impl Read, buf_out: impl Write, key: &[u8], chunk_size: usize) {
    let mut buf_reader = BufReader::new(buf_in);
    let mut buf_writer = BufWriter::new(buf_out);
    let mut chunk = vec![0u8; chunk_size];

    let salt = crypto::generate_salt().unwrap();
    buf_writer.write(&salt).unwrap();
    buf_writer.write(&chunk_size.to_be_bytes()).unwrap();

    let dkey = crypto::derive_key(key, &salt);
    let mut nchunk: usize = 0;

    loop {
        let nread = buf_reader.read(&mut chunk).unwrap();
        if nread == 0 {
            break;
        } else if nread != chunk_size {
            chunk.resize(nread, 0);
        }

        let mut nonce_sequence = crypto::CounterNonceSequence::new(&salt);
        nonce_sequence.counter = u32::try_from(nchunk).unwrap();

        let tag = crypto::aead_encrypt(&mut chunk, dkey, nonce_sequence).unwrap();

        buf_writer.write(&chunk).unwrap();
        buf_writer.write(tag.as_ref()).unwrap();
        nchunk += 1;
    }

    buf_writer.flush().unwrap();
}

pub fn buffer_decrypt(buf_in: impl Read, buf_out: impl Write, key: &[u8]) {
    let mut buf_reader = BufReader::new(buf_in);
    let mut buf_writer = BufWriter::new(buf_out);

    let mut salt = crypto::Salt::default();
    buf_reader.read(&mut salt).unwrap();
    let mut chunk_size_bytes = [0u8; 8];
    buf_reader.read(&mut chunk_size_bytes).unwrap();
    let chunk_size = usize::from_be_bytes(chunk_size_bytes) + TAG_LEN;
    let mut chunk = vec![0u8; chunk_size];

    let dkey = crypto::derive_key(key, &salt);
    let mut nchunk: usize = 0;

    loop {
        let nread = buf_reader.read(&mut chunk).unwrap();
        if nread == 0 {
            break;
        } else if nread != chunk_size {
            chunk.resize(nread, 0);
        }

        let mut nonce_sequence = crypto::CounterNonceSequence::new(&salt);
        nonce_sequence.counter = u32::try_from(nchunk).unwrap();

        let data = crypto::aead_decrypt(&mut chunk, dkey, nonce_sequence).unwrap();

        buf_writer.write(&data).unwrap();
        nchunk += 1;
    }

    buf_writer.flush().unwrap();
}
