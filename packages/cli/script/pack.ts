// What each platform's tarball holds. On macOS, `deadbolt` checks the agent with the `deadbolt-enclave`
// beside it (its pinned hash compiled in) before it sends a passphrase, so the two always ship together.

import { $ } from "bun"

export const platforms = ["linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64"]

export function files(platform: string): string[] {
  return platform.startsWith("darwin-") ? ["deadbolt", "deadbolt-enclave"] : ["deadbolt"]
}

/** Packs `dist/cli-<platform>/bin` into `dist/deadbolt-<platform>.tar.gz` and returns its SHA-256. */
export async function pack(dist: string, platform: string): Promise<string> {
  const bin = `${dist}/cli-${platform}/bin`
  const names = files(platform)
  for (const name of names) {
    if (!(await Bun.file(`${bin}/${name}`).exists())) throw new Error(`${bin}/${name} is missing`)
    await $`chmod 755 ${bin}/${name}`
  }
  const tarball = `${dist}/deadbolt-${platform}.tar.gz`
  await $`tar -czf ${tarball} -C ${bin} ${names}`
  return new Bun.CryptoHasher("sha256").update(await Bun.file(tarball).arrayBuffer()).digest("hex")
}
