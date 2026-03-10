class Leakwall < Formula
  desc "AI agent security platform — protect coding agents from secret leaks and tool poisoning"
  homepage "https://github.com/Kranium2002/leakwall"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Kranium2002/leakwall/releases/download/v0.1.0/leakwall-0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "682869aa2d1d1191955ae0bc215c743bff1d216ce797badb55aaa4552f706a80"
    else
      url "https://github.com/Kranium2002/leakwall/releases/download/v0.1.0/leakwall-0.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "7f51236f0eb13777a004109e61cfec86a4e549e1e0019c3b881749c12475bc4a"
    end
  end

  on_linux do
    url "https://github.com/Kranium2002/leakwall/releases/download/v0.1.0/leakwall-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "7c18c73e1da16800f1f63e05724f2c8722bdc447138ad57ceec22b200c983db8"
  end

  def install
    bin.install "leakwall"
  end

  test do
    assert_match "leakwall", shell_output("#{bin}/leakwall --version")
  end
end
