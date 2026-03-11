class Leakwall < Formula
  desc "AI agent security platform — protect coding agents from secret leaks and tool poisoning"
  homepage "https://github.com/Kranium2002/leakwall"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Kranium2002/leakwall/releases/download/v0.1.0/leakwall-0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "682a9bda93cbe5723716865a3a1ab16fd04c3f6bc23ab74b9dd14bbd631d17ee"
    else
      url "https://github.com/Kranium2002/leakwall/releases/download/v0.1.0/leakwall-0.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "e8179d8c9e98bb3cd35498941373d0023c93c5b75a24d94c9ee455059cc4c0d9"
    end
  end

  on_linux do
    url "https://github.com/Kranium2002/leakwall/releases/download/v0.1.0/leakwall-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "b1271c106e6d11837c577af2e5ee20590b96b3a947681783b4a05164d536468c"
  end

  def install
    bin.install "leakwall"
  end

  test do
    assert_match "leakwall", shell_output("#{bin}/leakwall --version")
  end
end
