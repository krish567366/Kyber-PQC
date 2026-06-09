# Kyber-PQC

Native **ML-KEM-512 (Kyber-512)** implementation in C with Python, Go, and Rust bindings.

**Bajpai Labs** · [hello@bajpailabs.com](mailto:hello@bajpailabs.com)  
**Homepage:** [quantum.postquantumlabs.in/kyber-pqc](https://quantum.postquantumlabs.in/kyber-pqc)

## Install

```bash
pip install kyber-pqc
```

## Distribution

| Channel | Install |
|---------|---------|
| PyPI | `pip install kyber-pqc` |
| Conan | `conan install kyber-pqc/2.0.0 -r bajpai` |
| Docker | `docker pull docker.bajpailabs.com/kyber-pqc:latest` |
| Raw | `raw.bajpailabs.com/kyber-pqc/v2.0.0/…` |
| Go | `go get github.com/krish567366/Kyber-PQC/go/kyberpqc@v2.0.0` |
| Rust | `cargo add kyber-pqc` |
| Homebrew | `brew tap bajpai-labs/tap && brew install kyber-pqc` |

Registry endpoints: `conan.bajpailabs.com` · `docker.bajpailabs.com` · `raw.bajpailabs.com`

## Usage

```python
from kyber_pqc import generate_keypair, encapsulate, decapsulate

kp = generate_keypair()
ct = encapsulate(kp.public_key)
shared_secret = decapsulate(ct.data, kp.private_key)
```

## Develop

```bash
make install
make test
```

## Release

```bash
git tag v2.0.0
git push origin v2.0.0
```

GitHub secrets: `BAJPAILABS_REGISTRY_USER`, `BAJPAILABS_REGISTRY_PASSWORD`, `CRATES_IO_TOKEN`, `PYPI_API_TOKEN` (optional), `MINISIGN_KEY`, `MINISIGN_PASSWORD` (optional), `HOMEBREW_TAP_GITHUB_TOKEN` (pushes formula to [bajpai-labs/homebrew-tap](https://github.com/bajpai-labs/homebrew-tap)).

### Homebrew

```bash
brew tap bajpai-labs/tap
brew install kyber-pqc
```

On each release, CI updates the tap formula, builds an arm64 macOS bottle, and uploads it to GitHub Releases.

### Artifact signing

One-time local setup:

```bash
minisign -G    # creates minisign.key (private) and minisign.pub (public)
```

Commit `minisign.pub` to this repo. Add GitHub Actions secrets:

- `MINISIGN_KEY` — full contents of `minisign.key`
- `MINISIGN_PASSWORD` — only if you set a passphrase on the key

Verify a release tarball:

```bash
minisign -Vm kyber-pqc-v2.0.0-x86_64-unknown-linux-gnu.tar.gz -p minisign.pub
# or
minisign -V kyber-pqc-v2.0.0-x86_64-unknown-linux-gnu.tar.gz -p minisign.pub
```

## License

MIT — see [LICENSE](LICENSE)
