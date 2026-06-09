# Installation

## Python (PyPI)

```bash
pip install kyber-pqc
```

## Homebrew

```bash
brew tap bajpai-labs/tap
brew install kyber-pqc
```

## Conan

```bash
conan remote add bajpai https://conan.bajpailabs.com --force
conan install kyber-pqc/2.1.1 -r bajpai
```

## Docker

```bash
docker pull docker.bajpailabs.com/repository/bajpailabs-docker/kyber-pqc:latest
```

## Go

```bash
go get github.com/krish567366/Kyber-PQC/go/kyberpqc@v2.1.1
```

## Rust

```bash
cargo add kyber-pqc
```

## From source

```bash
git clone https://github.com/krish567366/Kyber-PQC.git
cd Kyber-PQC
make install
make test
```
