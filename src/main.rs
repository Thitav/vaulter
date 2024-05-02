use std::fs::File;
use structopt::StructOpt;
mod crypto;
mod vault;

const CHUNK_SIZE: usize = 1024;

#[derive(StructOpt)]
#[structopt(name = "Vaulter", about = "Secure AEAD file encryption utility")]
enum Vaulter {
    #[structopt(about = "Encrypts a file")]
    Lock {
        #[structopt(name = "input file")]
        path_fin: String,
        #[structopt(name = "output file")]
        path_fout: String,
        key: String,
    },
    #[structopt(about = "Decrypts a file")]
    Unlock {
        #[structopt(name = "input file")]
        path_fin: String,
        #[structopt(name = "output file")]
        path_fout: String,
        key: String,
    },
}

fn vault_lock(path_fin: &String, path_fout: &String, key: &[u8]) {
    let file_in = File::open(path_fin).unwrap();
    let file_out = File::create(path_fout).unwrap();
    let file_size = usize::try_from(file_in.metadata().unwrap().len()).unwrap();

    vault::buffer_encrypt(file_in, file_out, key, CHUNK_SIZE, file_size);
}

fn vault_unlock(path_fin: &String, path_fout: &String, key: &[u8]) {
    let file_in = File::open(path_fin).unwrap();
    let file_out = File::create(path_fout).unwrap();
    let file_size = usize::try_from(file_in.metadata().unwrap().len()).unwrap();

    vault::buffer_decrypt(file_in, file_out, key, CHUNK_SIZE, file_size);
}

fn main() {
    let opt = Vaulter::from_args();

    match opt {
        Vaulter::Lock {
            path_fin,
            path_fout,
            key,
        } => {
            vault_lock(&path_fin, &path_fout, key.as_bytes());
        }
        Vaulter::Unlock {
            path_fin,
            path_fout,
            key,
        } => {
            vault_unlock(&path_fin, &path_fout, key.as_bytes());
        }
    }
}
