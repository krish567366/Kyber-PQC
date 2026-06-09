import platform

from setuptools import Extension, setup

VENDOR_SOURCES = [
    "c/vendor/kyber512/kem.c",
    "c/vendor/kyber512/indcpa.c",
    "c/vendor/kyber512/polyvec.c",
    "c/vendor/kyber512/poly.c",
    "c/vendor/kyber512/ntt.c",
    "c/vendor/kyber512/cbd.c",
    "c/vendor/kyber512/reduce.c",
    "c/vendor/kyber512/verify.c",
    "c/vendor/kyber512/fips202.c",
    "c/vendor/kyber512/symmetric-shake.c",
    "c/vendor/kyber512/randombytes.c",
]

NATIVE_SOURCES = [
    "c/src/python_module.c",
    "c/src/kyber_pqc.c",
    "c/src/secure.c",
] + VENDOR_SOURCES

extra_compile_args = ["-O3", "-Wall"]
if platform.machine() in {"arm64", "aarch64"}:
    extra_compile_args.append("-mcpu=native")

setup(
    ext_modules=[
        Extension(
            "kyber_pqc._native",
            sources=NATIVE_SOURCES,
            include_dirs=["c/include", "c/src", "c/vendor/kyber512"],
            define_macros=[("KYBER_K", "2")],
            extra_compile_args=extra_compile_args,
        )
    ]
)
