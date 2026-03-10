class Leakwall < Formula
  desc "AI agent security platform — protect coding agents from secret leaks and tool poisoning"
  homepage "https://github.com/Kranium2002/leakwall"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Kranium2002/leakwall/releases/download/v0.1.0/leakwall-0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "6b3a0131a404ea6a5fd9d41b20236a0ab00df7b32931b8f31d2ff7c14c5356a1"
    else
      url "https://github.com/Kranium2002/leakwall/releases/download/v0.1.0/leakwall-0.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "aadf20d00b9e760b65dc04848cf04d15b5a989fa8926f1d06612f78345adac6b"
    end
  end

  on_linux do
    url "https://github.com/Kranium2002/leakwall/releases/download/v0.1.0/leakwall-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "2807d4ab37d860cad79c98ec36815108e9d7447faa03c12a5df947a357b84fbe"
  end

  def install
    bin.install "leakwall"
  end

  test do
    assert_match "leakwall", shell_output("#{bin}/leakwall --version")
  end
end
