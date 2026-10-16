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
        <pre>{`$ deadbolt init\n`}{out("passphrase: \nrepeat passphrase: \ncreated vault personal (default)")}{`\n\n$ deadbolt new login username=kit url=github.com\n`}{out("3f9a")}{`\n$ deadbolt get github\n`}{out("Xk2mv9QpRt7…")}{`\n\n# on a new phone\n$ deadbolt join\n`}{out("DBPAIRAGMRLX…   (and a qr code)")}{`\n\n# on a device you already have\n$ deadbolt pair DBPAIRAGMRLX…\n`}{out("code 411308: adding device phone\nconfirm code 411308 matches the other device? [y/N] y\nadded phone to personal")}</pre>
      </section>

      <section>
        <h2>how it works</h2>
        <ol className="steps">
          <li><Justified text="each device has its own key. it's the device's identity on the network and signs everything the device writes. it never leaves the device, and on disk it's sealed under your passphrase." /></li>
          <li><Justified text="every change is a signed entry in that device's own log. entries point at what their author had seen, never at a clock, so devices that were apart merge the same way in any order." /></li>
          <li><Justified text="devices sync directly over iroh: compare what each has, send what the other is missing. the connection is end-to-end encrypted and authenticated to device keys." /></li>
          <li><Justified text="a device that isn't a member is refused before it can send or receive a single byte. remove a device and its open connections close at once." /></li>
          <li><Justified text="a new device joins by pairing with one that's already in. both screens show the same six digits; you confirm they match." /></li>
        </ol>
        <a className="cta" href="/architecture/">walk through the architecture →</a>
      </section>

      <section>
        <h2>trade-offs</h2>
        <dl className="facts">
          <div><dt>no recovery</dt><Justified as="dd" text="lose every device and the vault is gone. there is no server holding a copy and no reset email. pair a second device early." /></div>
          <div><dt>removal is a promise about the future</dt><Justified as="dd" text="a removed device can't sync anything new, but it keeps what it already had. rotate the passwords it could see." /></div>
          <div><dt>it's early</dt><Justified as="dd" text="deadbolt is a design with working code: a cli, a background agent, pairing, sync and a bitwarden import. no apps or browser extension yet." /></div>
        </dl>
      </section>

      <footer>deadbolt · <a className="link" href="/architecture/">architecture</a> · <a className="link" href={github}>github</a> · <a className="link" href="/mock.html">original mock</a></footer>
    </main>
  </div>
}

createRoot(document.getElementById("root")!).render(<StrictMode><Landing /></StrictMode>)
