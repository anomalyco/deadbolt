# Welcome screen concept

Status: concept, not built. A prototype of the desktop app's first screen, from a design session with Dax (2026-10-29).

Open `index.html` in a browser (a static file, no build). Move the cursor around and hover the two rows.

## The screen

No logo or wordmark. An animation above one card with two rows, each with an icon tile: **Create a vault** and **Join my devices**. Nothing else on screen. Style follows Hex's onboarding: flat near-black, Inter, grey controls, color only for success.

## The animation: the password dots

The eight `••••••••` of a password field, alive. They carry the idea: your secrets are yours and move only between your devices.

- **At rest:** the dots hop in a wave. When the cursor comes near they grow small worried eyes and flee.
- **Hover Create a vault:** they huddle into a tight 3×3 safe with a keyhole in the empty centre.
- **Hover Join my devices:** they split into three groups at the corners of an equilateral triangle. Faint links draw between the groups and pulses ping around the triangle using OpenTunnel's pulse vocabulary (`opentunnel:packages/website/src/graphics/Pulse.tsx`): light gathers at the origin, travels with ease-in-out, leaves a heat trail that cools in 300 ms, and is absorbed with an expanding landing ring. The group a pulse lands on hops.

The prototype also keeps an alternative, **the keyhole** (a glossy keyhole character with eyes that follow the cursor, squints when you get close, and bats away a `password: hunter2` sticky note).

## The rest of the flow

Accepted as is for now (generated mock-ups, not app pixels):

- `h3-join-code.png`: Join shows the four-word code large with Copy and "Waiting for your other device" at the top right.
- `h4-passphrase.png`: the passphrase is asked last, after "Joined personal from laptop".
- `h5-done.png`: success badge, "You're in", Open Deadbolt.

## Building it

Port to Rune in `crates/app` onboarding with Rune springs. The dots and pulses are small vector shapes; keep idle drawing cheap (draw only while something moves, stop when the window is hidden) and respect reduced motion (dots rest in a row, no flight; Join shows the triangle and links without pulses).
