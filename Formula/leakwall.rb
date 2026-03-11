class Leakwall < Formula
  desc "AI agent security platform — protect coding agents from secret leaks and tool poisoning"
  homepage "https://github.com/Kranium2002/leakwall"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Kranium2002/leakwall/releases/download/v0.1.0/leakwall-0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "87337c5f4ce849dc058a8065b3bbf6ce0adc8df734bd46c6bf5d177e864df858"
    else
      url "https://github.com/Kranium2002/leakwall/releases/download/v0.1.0/leakwall-0.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "f8af2ddf5c1ae6f4c50d0deb5ad7979ef4d093c08e786e1ef9fe0bb9fe4d2c8c"
    end
  end

  on_linux do
    url "https://github.com/Kranium2002/leakwall/releases/download/v0.1.0/leakwall-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "cbf513b89681ec07c3d72b7ea884a56c02476388ef9d01c1397754b05069d0b3"
  end

  def install
    bin.install "leakwall"
  end

  test do
    assert_match "leakwall", shell_output("#{bin}/leakwall --version")
  end
end
