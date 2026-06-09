FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

RUN pip install --no-cache-dir build \
    && python -m build --wheel \
    && pip install --no-cache-dir dist/*.whl

FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/krish567366/Kyber-PQC"
LABEL org.opencontainers.image.url="https://quantum.postquantumlabs.in/kyber-pqc"
LABEL org.opencontainers.image.description="Kyber-PQC ML-KEM-512 native implementation"
LABEL org.opencontainers.image.licenses="MIT"

COPY --from=builder /usr/local /usr/local

RUN useradd --create-home --shell /bin/bash kyber
USER kyber

CMD ["python", "-c", "from kyber_pqc import generate_keypair, native_backend; kp=generate_keypair(); print(native_backend(), len(kp.public_key))"]
