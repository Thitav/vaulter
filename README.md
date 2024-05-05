# Vaulter

Secure AEAD file encryption utility.

## Installation

Install [Rust](https://www.rust-lang.org/tools/install) and run:
```bash
git clone https://github.com/Thitav/vaulter
cd vaulter
cargo install
```

## Usage

Encrypt:
```bash
vaulter lock <input file> <output file> <key>
```
Decrypt:
```bash
vaulter unlock <input file> <output file> <key>
```
Run `vaulter --help` for more information.

## License

[MIT](https://choosealicense.com/licenses/mit/)
