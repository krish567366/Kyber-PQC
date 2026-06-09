# Usage

## Python

```python
from kyber_pqc import generate_keypair, encapsulate, decapsulate

kp = generate_keypair()
ct = encapsulate(kp.public_key)
shared_secret = decapsulate(ct.data, kp.private_key)
```

## CLI

```bash
kyber-pqc version
kyber-pqc keygen public.hex.pem private.hex.pem
```

## C

```c
#include "kyber_pqc.h"

kyber_pqc_keypair_t kp;
kyber_pqc_keypair(&kp);
```

See the [source repository](https://github.com/krish567366/Kyber-PQC) for Go, Rust, and Conan examples.
