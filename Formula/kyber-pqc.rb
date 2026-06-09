class KyberPqc < Formula
  desc "Native ML-KEM-512 (Kyber-512) post-quantum key encapsulation"
  homepage "https://quantum.postquantumlabs.in/kyber-pqc"
  # Mirrored from homebrew-tap/Formula/kyber-pqc.rb (updated on each release).
  url "https://github.com/krish567366/Kyber-PQC/archive/refs/tags/v2.0.0.tar.gz"
  sha256 "UPDATE_ON_RELEASE"
  license "MIT"
  head "https://github.com/krish567366/Kyber-PQC.git", branch: "main"

  depends_on "cmake" => :build

  def install
    system "cmake", "-S", "c", "-B", "build",
                    "-DCMAKE_INSTALL_PREFIX=#{prefix}",
                    "-DCMAKE_BUILD_TYPE=Release",
                    "-DPROJECT_VERSION=#{version}"
    system "cmake", "--build", "build"
    system "cmake", "--install", "build"
  end

  test do
    assert_match "kyber-pqc #{version}", shell_output("#{bin}/kyber-pqc version")
    pub = testpath/"public.hex.pem"
    priv = testpath/"private.hex.pem"
    system bin/"kyber-pqc", "keygen", pub, priv
    assert_path_exists pub
    assert_path_exists priv
  end
end
