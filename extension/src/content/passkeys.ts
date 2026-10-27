// Isolated-world end of the private channel to passkey-hook.ts (MAIN world):
// hands the hook one MessagePort before page scripts run, relays its WebAuthn
// requests to the background and returns the answers. Ported from Foyer
// (github.com/R44VC0RP/foyer, src/autofill/channel.ts, by Ryan Vogel).
//
// Foyer offered a new port whenever the page said hello and took the first
// port acknowledged on as the hook's, so a page could take an offer, ack it
// first and become the channel. Here there is exactly one offer, made at
// document_start: the hook's capturing listener, installed before any page
// script, takes it and stops it reaching the page. Only an ack on that port
// opens the channel, and nothing else is ever offered.

import type { HookReply, ToBackground } from "../messages"

type HookMessage = { id?: unknown; op?: unknown; payload?: unknown }

/**
 * Whether this frame's Permissions Policy lets it make the call. Read here,
 * in the isolated world, where page scripts can't change the answer.
 */
function allows(op: "get" | "create"): boolean {
  const doc = document as Document & { permissionsPolicy?: FeaturePolicy; featurePolicy?: FeaturePolicy }
  try {
    return (doc.permissionsPolicy ?? doc.featurePolicy)?.allowsFeature(`publickey-credentials-${op}`) === true
  } catch {
    return false
  }
}

interface FeaturePolicy {
  allowsFeature(feature: string): boolean
}

export function initPasskeyChannel(send: <T>(message: ToBackground) => Promise<T | null>) {
  const channel = new MessageChannel()
  const port = channel.port1
  let acked = false
  port.onmessage = (event: MessageEvent<HookMessage>) => {
    const message = event.data
    if (!message || typeof message.op !== "string") return
    if (message.op === "ack") return void (acked = true)
    if (!acked || typeof message.id !== "number" || !Number.isSafeInteger(message.id)) return
    const id = message.id
    if (message.op === "cancel") return void send({ type: "pk:cancel", request: id })
    if (message.op !== "get" && message.op !== "create") return
    const op = message.op
    void send<HookReply>({ type: op === "get" ? "pk:get" : "pk:create", request: id, options: message.payload, allowed: allows(op) }).then((reply) => {
      // No answer (the extension reloaded, or the worker went away): the browser's own flow.
      if (!reply) return port.postMessage({ id, ok: true, result: { fallback: true } })
      if ("error" in reply) return port.postMessage({ id, ok: false, error: reply.error })
      port.postMessage({ id, ok: true, result: "fallback" in reply ? { fallback: true } : reply.credential })
    })
  }
  window.postMessage({ deadbolt: "passkey-port" }, "*", [channel.port2])
}
