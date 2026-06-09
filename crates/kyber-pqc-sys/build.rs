use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let c_root = manifest_dir.join("../../c");

    let sources = [
        "src/kyber_pqc.c",
        "src/kyber_pem.c",
        "src/secure.c",
        "vendor/kyber512/kem.c",
        "vendor/kyber512/indcpa.c",
        "vendor/kyber512/polyvec.c",
        "vendor/kyber512/poly.c",
        "vendor/kyber512/ntt.c",
        "vendor/kyber512/cbd.c",
        "vendor/kyber512/reduce.c",
        "vendor/kyber512/verify.c",
        "vendor/kyber512/fips202.c",
        "vendor/kyber512/symmetric-shake.c",
        "vendor/kyber512/randombytes.c",
    ];

    let mut build = cc::Build::new();
    build
        .define("KYBER_K", "2")
        .include(c_root.join("include"))
        .include(c_root.join("src"))
        .include(c_root.join("vendor/kyber512"))
        .flag_if_supported("-O3")
        .flag_if_supported("-Wall")
        .flag_if_supported("-Wextra");

    for source in sources {
        build.file(c_root.join(source));
        println!("cargo:rerun-if-changed={}", c_root.join(source).display());
    }

    build.compile("kyber_pqc");
    println!("cargo:rustc-link-lib=static=kyber_pqc");
}
