#!/usr/bin/env bun
// Publishes the CLI binaries: a GitHub release with one tarball per platform
// and a SHA256SUMS file (both used by the install script), and the Homebrew
// formula in anomalyco/homebrew-tap, skipped when its credentials are missing.

import { $ } from "bun"
import { fileURLToPath } from "url"
import pkg from "../package.json"

const dir = fileURLToPath(new URL("..", import.meta.url))
process.chdir(dir)

const version = pkg.version
const tag = `v${version}`
const repo = "anomalyco/deadbolt"
const description = "Decentralized password manager"
const download = (platform: string) =>
  `https://github.com/${repo}/releases/download/${tag}/deadbolt-${platform}.tar.gz`

const platforms = ["linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64"]
const sha: Record<string, string> = {}
for (const platform of platforms) {
  const tarball = `./dist/deadbolt-${platform}.tar.gz`
  await $`chmod 755 ./dist/cli-${platform}/bin/deadbolt`
  await $`tar -czf ${tarball} -C ./dist/cli-${platform}/bin deadbolt`
  sha[platform] = new Bun.CryptoHasher("sha256").update(await Bun.file(tarball).arrayBuffer()).digest("hex")
}
await Bun.write(
  "./dist/SHA256SUMS",
  platforms.map((platform) => `${sha[platform]}  deadbolt-${platform}.tar.gz\n`).join(""),
)

// GitHub release
if ((await $`gh release view ${tag} --repo ${repo}`.nothrow().quiet()).exitCode === 0) {
  console.log(`release ${tag} already exists`)
} else {
  const assets = [...platforms.map((platform) => `./dist/deadbolt-${platform}.tar.gz`), "./dist/SHA256SUMS"]
  await $`gh release create ${tag} ${assets} --repo ${repo} --title ${tag} --generate-notes`
}

// Homebrew: brew install anomalyco/tap/deadbolt
const formula = `class Deadbolt < Formula
  desc "${description}"
  homepage "https://deadbolt.pw"
  version "${version}"

  on_macos do
    on_arm do
      url "${download("darwin-arm64")}"
      sha256 "${sha["darwin-arm64"]}"
    end
    on_intel do
      url "${download("darwin-x64")}"
      sha256 "${sha["darwin-x64"]}"
    end
  end

  on_linux do
    on_arm do
      url "${download("linux-arm64")}"
      sha256 "${sha["linux-arm64"]}"
    end
    on_intel do
      url "${download("linux-x64")}"
      sha256 "${sha["linux-x64"]}"
    end
  end

  def install
    bin.install "deadbolt"
  end

  test do
    system bin/"deadbolt", "--version"
  end
end
`
// CI writes the tap's deploy key (HOMEBREW_TAP_KEY) to an SSH host alias, homebrew-tap.github.com.
if (process.env.HOMEBREW_TAP_KEY) {
  const tap = "git@homebrew-tap.github.com:anomalyco/homebrew-tap.git"
  await $`rm -rf ./dist/homebrew-tap`
  await $`git clone --depth 1 ${tap} ./dist/homebrew-tap`
  await Bun.write("./dist/homebrew-tap/deadbolt.rb", formula)
  await $`git add deadbolt.rb`.cwd("./dist/homebrew-tap")
  if ((await $`git diff --cached --quiet`.cwd("./dist/homebrew-tap").nothrow()).exitCode !== 0) {
    await $`git commit -m ${`deadbolt ${version}`}`.cwd("./dist/homebrew-tap")
    await $`git push`.cwd("./dist/homebrew-tap")
  }
} else {
  console.warn("HOMEBREW_TAP_KEY is not set; skipping Homebrew")
}
