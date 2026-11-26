import { StrictMode, useState } from "react"
import { createRoot } from "react-dom/client"
import { Ink } from "../print/Ink"
import { Justified } from "../print/Justified"
import { Masthead } from "../print/Masthead"
import { MeshScene } from "./MeshScene"
import "../styles.css"

const github = "https://github.com/anomalyco/deadbolt"

const installs = {
  curl: "curl -fsSL https://deadbolt.pw/install | sh",
  brew: "brew install anomalyco/tap/deadbolt",
  source: "git clone git@github.com:anomalyco/deadbolt.git && cargo install --path deadbolt/crates/cli",
} as const
type Manager = keyof typeof installs

function Install() {
  const [manager, setManager] = useState<Manager>("curl")
  return <div className="install">
    <div className="tabs" role="tablist">
      {(Object.keys(installs) as Manager[]).map(name => <button key={name} type="button" role="tab" aria-selected={manager === name} data-current={manager === name || undefined} onClick={() => setManager(name)}>{name}</button>)}
      <a href={github} target="_blank" rel="noopener">github</a>
    </div>
    <div className="command">$ {installs[manager]}</div>
  </div>
}

const out = (text: string) => <span className="output">{text}</span>

function Landing() {
  return <div className="site">
    <Ink />
    <main>
      <Masthead />

      <div className="bleed"><MeshScene /></div>

      <Justified className="description" text="a password manager with no server. your devices hold the vault and sync with each other directly, end-to-end encrypted. a new device joins only by pairing with one you already have. no accounts. nothing of ours to breach." />

      <Install />

      <section>
        <h2>cli</h2>
        <pre>{`$ deadbolt init\n`}{out("passphrase: \nrepeat passphrase: \ncreated vault personal (default)")}{`\n\n$ deadbolt new login username=alex url=github.com\n`}{out("3f9a")}{`\n$ deadbolt get github\n`}{out("Xk2mv9QpRt7…")}{`\n\n# on a new phone\n$ deadbolt join\n`}{out("DBPAIRAGMRLX…   (and a qr code)")}{`\n\n# on a device you already have\n$ deadbolt approve DBPAIRAGMRLX…\n`}{out("code 411308: adding device phone\nconfirm code 411308 matches the other device? [y/N] y\nadded phone to personal")}</pre>
      </section>

      <section>
        <h2>how it works</h2>
        <ol className="steps">
          <li><Justified text="each device has its own keys, derived from a seed that never leaves it and is sealed under your passphrase on disk: one signs everything the device writes, one receives the vault's epoch keys, and a separate one is its identity on the network." /></li>
          <li><Justified text="every change is a signed frame, sealed under the vault's current epoch key and appended to files that are never rewritten. frames point at what their author had seen, never at a clock, so devices that were apart merge the same way in any order." /></li>
          <li><Justified text="devices sync directly over iroh: compare what each has, send what the other is missing. the connection is end-to-end encrypted and authenticated to device keys." /></li>
          <li><Justified text="a device that isn't a member is refused before it can send or receive a single byte. remove a device and its open connections close at once." /></li>
          <li><Justified text="a new device joins by pairing with one that's already in. both screens show the same six digits; you confirm they match." /></li>
        </ol>
        <a className="cta" href="/architecture/">walk through the architecture →</a>
      </section>

      <section>
        <h2>trade-offs</h2>
        <dl className="facts">
          <div><dt>the recovery kit is the only way back</dt><Justified as="dd" text="each vault has a 24-word recovery kit. lose every device and the kit brings the vault back; lose the kit too and it's gone. there is no server holding a copy and no reset email." /></div>
          <div><dt>removal is a promise about the future</dt><Justified as="dd" text="a removed device can't sync anything new, but it keeps what it already had. rotate the passwords it could see." /></div>
          <div><dt>it's early</dt><Justified as="dd" text="deadbolt is alpha: a cli, a background daemon, a desktop app, a chromium extension, pairing, sync and imports all work, and they still change from build to build." /></div>
        </dl>
      </section>

      <footer>deadbolt · <a className="link" href="/architecture/">architecture</a> · <a className="link" href="/changelog">changelog</a> · <a className="link" href={github}>github</a> · <a className="link" href="/mock.html">original mock</a></footer>
    </main>
  </div>
}

createRoot(document.getElementById("root")!).render(<StrictMode><Landing /></StrictMode>)
