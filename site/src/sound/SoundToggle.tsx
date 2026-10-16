import { play, setEnabled } from "./sound"
import { useSoundEnabled } from "./useCues"
import "./sound.css"

// The page's sound switch: "sound off" / "sound on" in the text face, with a small speaker. Off
// until the visitor turns it on; turning it on plays the switch's own click.

export function SoundToggle({ className }: { className?: string }) {
  const on = useSoundEnabled()
  return (
    <button
      type="button"
      className={className ? `sound-toggle ${className}` : "sound-toggle"}
      aria-pressed={on}
      title={on ? "turn sound off" : "turn sound on"}
      onClick={() => {
        setEnabled(!on)
        if (!on) play("toggle")
      }}
    >
      <svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true" focusable="false">
        <path className="sound-toggle-body" d="M2 6.2h2.3l3.3-2.7v9L4.3 9.8H2z" />
        {on ? (
          <path className="sound-toggle-waves" d="M10.2 5.7a3.1 3.1 0 0 1 0 4.6M12.1 3.9a5.6 5.6 0 0 1 0 8.2" />
        ) : (
          <path className="sound-toggle-waves" d="M10.6 6.2l3.4 3.6M14 6.2l-3.4 3.6" />
        )}
      </svg>
      <span>sound</span>
      <span className="sound-toggle-state" aria-hidden="true">
        {on ? "on" : "off"}
      </span>
    </button>
  )
}
