import { expect, test } from "bun:test"
import { $ } from "bun"
import { mkdtemp, mkdir, rm } from "fs/promises"
import { tmpdir } from "os"
import { join } from "path"
import { pack, platforms } from "./pack"

async function dist(present: Record<string, string[]>) {
  const dir = await mkdtemp(join(tmpdir(), "deadbolt-pack-"))
  for (const [platform, names] of Object.entries(present)) {
    await mkdir(`${dir}/cli-${platform}/bin`, { recursive: true })
    for (const name of names) await Bun.write(`${dir}/cli-${platform}/bin/${name}`, name)
  }
  return dir
}

test("macOS tarballs carry deadbolt-enclave beside deadbolt", async () => {
  const dir = await dist(Object.fromEntries(platforms.map((p) => [p, ["deadbolt", "deadbolt-enclave"]])))
  try {
    for (const platform of platforms) {
      await pack(dir, platform)
      const listed = (await $`tar -tzf ${dir}/deadbolt-${platform}.tar.gz`.text()).trim().split("\n").sort()
      expect(listed).toEqual(platform.startsWith("darwin-") ? ["deadbolt", "deadbolt-enclave"] : ["deadbolt"])
    }
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test("a macOS build without its helper doesn't pack", async () => {
  const dir = await dist({ "darwin-arm64": ["deadbolt"] })
  try {
    await expect(pack(dir, "darwin-arm64")).rejects.toThrow("deadbolt-enclave is missing")
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
