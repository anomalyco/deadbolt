class Deadbolt < Formula
  desc "Decentralized password manager"
  homepage "https://deadbolt.pw"

  on_macos do
    on_arm do
      url "@MACOS_ARM64_URL@"
      sha256 "@MACOS_ARM64_SHA256@"
    end
    on_intel do
      url "@MACOS_X64_URL@"
      sha256 "@MACOS_X64_SHA256@"
    end
  end

  on_linux do
    on_arm do
      url "@LINUX_ARM64_URL@"
      sha256 "@LINUX_ARM64_SHA256@"
    end
    on_intel do
      url "@LINUX_X64_URL@"
      sha256 "@LINUX_X64_SHA256@"
    end
  end

  def install
    bin.install "deadbolt"
    # The Touch ID helper; the agent runs it only from beside its own executable.
    bin.install "deadbolt-enclave" if OS.mac?
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/deadbolt --version")
  end
end
