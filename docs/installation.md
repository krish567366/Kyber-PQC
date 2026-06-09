# Kyber-PQC Installation Guide

**Homepage:** [quantum.postquantumlabs.in/kyber-pqc](https://quantum.postquantumlabs.in/kyber-pqc)  
**Documentation:** [quantum.postquantumlabs.in/docs/kyber-pqc](https://quantum.postquantumlabs.in/docs/kyber-pqc)  
**Contact:** Bajpai Labs · [hello@bajpailabs.com](mailto:hello@bajpailabs.com)

## Requirements

- Python 3.10+
- C compiler (clang or gcc) for the native extension
- Go 1.21+ with cgo enabled (optional, for Go bindings)

## Production Installation

```bash
pip install kyber-pqc
```

This compiles the native ML-KEM-512 core during install.

## Development Installation

```bash
git clone https://github.com/krish567366/Kyber-PQC
cd Kyber-PQC
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
make test
```

## C Library

```bash
make -C c test
```

## Go Bindings

```bash
make -C c lib
cd go && CGO_ENABLED=1 go test ./...
```
