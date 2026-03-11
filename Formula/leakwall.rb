class Leakwall < Formula
  desc "AI agent security platform — protect coding agents from secret leaks and tool poisoning"
  homepage "https://github.com/Kranium2002/leakwall"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Kranium2002/leakwall/releases/download/v0.1.0/leakwall-0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "f6240f86666b2fb88043f38c588aa0fcf11e67161e0be6cf98125d846cdd4163"
    else
      url "https://github.com/Kranium2002/leakwall/releases/download/v0.1.0/leakwall-0.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "bc53085d0f74455dfee32420ed2fbf758d4c5177ee7ac2a957d40cc52c5bd930"
    end
  end

  on_linux do
    url "https://github.com/Kranium2002/leakwall/releases/download/v0.1.0/leakwall-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "388177d236d17f1ba5dedb9522945f05dba392d5e29e370cf07b337276cc8db9"
  end

  def install
    bin.install "leakwall"
  end

  test do
    assert_match "leakwall", shell_output("#{bin}/leakwall --version")
  end
end
