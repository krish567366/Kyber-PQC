# Kyber-512 Hex PEM Format

All language bindings use the same hex-encoded PEM format for key exchange
artifacts.

## Block Types

| PEM label | Binary size |
|-----------|-------------|
| `KYBER512 PUBLIC KEY` | 800 bytes |
| `KYBER512 PRIVATE KEY` | 1632 bytes |
| `KYBER512 CIPHERTEXT` | 768 bytes |
| `KYBER512 SHARED SECRET` | 32 bytes |

## Example

```pem
-----BEGIN KYBER512 PUBLIC KEY-----
a1031f7c2481d08740f47b561aabd6ee06d5f3ddbfbf5ad1e60f6cb68a8a...
-----END KYBER512 PUBLIC KEY-----
```

Rules:

- Payload is lowercase hexadecimal.
- Lines are wrapped at 64 characters.
- Private key files should be written with `0600` permissions.

## Language Support

- Python: `encode_pem`, `decode_pem`, `write_pem_file`, `read_pem_file`
- C: `kyber_pem_encode`, `kyber_pem_decode`, `kyber_pem_write_file`
- Go: `EncodePEM`, `DecodePEM`, `WritePEMFile`, `ReadPEMFile`

Recommended private key filename: `private.hex.pem`
