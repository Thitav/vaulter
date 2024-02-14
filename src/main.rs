use crypto::SALT_LEN;
use ring::aead::chacha20_poly1305_openssh::TAG_LEN;
use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    str,
};
// use structopt::StructOpt;

mod crypto;

const CHUNK_SIZE: usize = 3;

// #[derive(Debug, StructOpt)]
// #[structopt(name = "example", about = "An example of StructOpt usage.")]
// struct Opt {
//     #[structopt(name = "ACTION")]
//     file_name: Option<String>,
// }

fn vault_lock(key: &[u8], in_fp: &str, out_fp: &str) {
    let in_file = File::open(in_fp).unwrap();
    let fsize = in_file.metadata().unwrap().len() as usize;
    let out_file = File::create(out_fp).unwrap();

    let mut buf_reader = BufReader::new(in_file);
    let mut buf_writer = BufWriter::new(out_file);
    let mut chunk = vec![0u8; CHUNK_SIZE];

    let salt = crypto::generate_salt().unwrap();
    buf_writer.write_all(&salt).unwrap();
    let dkey = crypto::derive_key(key, &salt);

    for n in 0..fsize.div_ceil(CHUNK_SIZE) {
        buf_reader.read(&mut chunk).unwrap();

        let mut nonce_sequence = crypto::CounterNonceSequence::new(&salt);
        nonce_sequence.counter += n as u32;
        let tag = crypto::aead_encrypt(dkey, &mut chunk, nonce_sequence).unwrap();

        buf_writer.write(&chunk).unwrap();
        buf_writer.write_all(tag.as_ref()).unwrap();
    }

    buf_writer.flush().unwrap();
}

fn vault_unlock(key: &[u8], in_fp: &str, out_fp: &str) {
    let in_file = File::open(in_fp).unwrap();
    let fsize = in_file.metadata().unwrap().len() as usize;
    let out_file = File::create(out_fp).unwrap();

    let mut buf_reader = BufReader::new(in_file);
    let mut buf_writer = BufWriter::new(out_file);
    let mut chunk = vec![0u8; CHUNK_SIZE + TAG_LEN];

    let mut salt = crypto::Salt::default();
    buf_reader.read_exact(&mut salt).unwrap();
    let dkey = crypto::derive_key(key, &salt);

    for n in 0..(fsize - SALT_LEN).div_ceil(CHUNK_SIZE + TAG_LEN) {
        buf_reader.read(&mut chunk).unwrap();

        let mut nonce_sequence = crypto::CounterNonceSequence::new(&salt);
        nonce_sequence.counter += n as u32;
        let data = crypto::aead_decrypt(dkey, &mut chunk, nonce_sequence).unwrap();

        buf_writer.write(&data).unwrap();
    }

    buf_writer.flush().unwrap();
}

fn main() {
    // let opt = Opt::from_args();

    let k = "abc".as_bytes();
    vault_lock(k, "test.txt", "test.vault");
    vault_unlock(k, "test.vault", "test.out.txt")
}
