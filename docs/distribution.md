# Distribution

| Channel | Location |
|---------|----------|
| PyPI | `pip install kyber-pqc` |
| Conan | `conan.bajpailabs.com` |
| Docker | `docker.bajpailabs.com/repository/bajpailabs-docker/kyber-pqc` |
| Raw artifacts | `raw.bajpailabs.com/kyber-pqc/v{TAG}/` |
| GitHub Releases | [releases](https://github.com/krish567366/Kyber-PQC/releases) |
| Homebrew | [bajpai-labs/homebrew-tap](https://github.com/bajpai-labs/homebrew-tap) |
| crates.io | `kyber-pqc` |

## Release artifacts

Tagged releases may include:

- Native tarballs (`linux`, `macOS`)
- Python wheels and sdist
- SBOM (`sbom.spdx.json`, `cyclonedx.json`)
- minisign signatures (`.sig`) when configured

Verify signed tarballs:

```bash
minisign -Vm kyber-pqc-v2.1.1-x86_64-unknown-linux-gnu.tar.gz -p minisign.pub
```
