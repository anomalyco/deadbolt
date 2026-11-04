import type { Mark } from "../Masthead"
import { KeyholePrint } from "../KeyholePrint"
import { Bolt } from "./Bolt"
import { Frame } from "./Frame"
import { Glyph } from "./Glyph"
import { Halftone } from "./Halftone"
import { Heartbeat } from "./Heartbeat"
import { Plate } from "./Plate"
import { Registration } from "./Registration"
import { Shackle } from "./Shackle"
import { Stencil } from "./Stencil"
import { Stipple } from "./Stipple"

// Candidates for the masthead's square, for Dax to pick from at /marks/ (dev only). Each inverts the print: the
// lock is the red, and whatever is around it is quiet. Number 0 is today's mark, for comparison.

export type MarkEntry = { name: string; idea: string; label: string; Mark: Mark }

export const marks: MarkEntry[] = [
  { name: "current", idea: "Today's print: a red dithered burst with a black keyhole knocked out of it.", label: "A keyhole", Mark: KeyholePrint },
  { name: "frame", idea: "A solid red padlock in a hairline square that draws itself in.", label: "A padlock", Mark: Frame },
  { name: "stipple", idea: "The print inside out: a stippled red keyhole over a dim, sparse burst.", label: "A keyhole", Mark: Stipple },
  { name: "shackle", idea: "A heavy red outline padlock whose shackle drops shut on load.", label: "A padlock", Mark: Shackle },
  { name: "heartbeat", idea: "A solid red keyhole that thumps and sends out thin dark-red rings.", label: "A keyhole", Mark: Heartbeat },
  { name: "stencil", idea: "A heavy stencil padlock, Anton's weight, sprayed on with faint overspray.", label: "A padlock", Mark: Stencil },
  { name: "bolt", idea: "A red cylinder turns and throws a red bolt into a hairline strike plate.", label: "A deadbolt", Mark: Bolt },
  { name: "register", idea: "A red keyhole proof with dark-red crop ticks; a second pass slides into register.", label: "A keyhole", Mark: Registration },
  { name: "halftone", idea: "A halftone red padlock with a faint halo of small dots.", label: "A padlock", Mark: Halftone },
  { name: "glyph", idea: "No square: just a small red padlock, icon-sized.", label: "A padlock", Mark: Glyph },
  { name: "plate", idea: "A keyhole lit red from behind, cut through a dark plate with four screws.", label: "A keyhole", Mark: Plate },
]
