# Ephor brand

The Ephor mark is **five bronze nodes evenly spaced in a ring around an untouched,
hollow core** — five overseers watching a centre they never enter. It replaces an
obsolete predecessor mark: a stylised letter "W" built from five routing nodes,
which named the previous product and no longer fit once the product became *Ephor*.
The five nodes carried forward (they were always the right count for the concept);
the shape they form no longer spells a letter.

Ephor is a **sibling** of the [Envoir](../../envoir) mark, not a clone: same build
quality and lockup conventions (rounded-square tile, mono variant via `currentColor`,
wordmark/og-image pattern), deliberately different hue and a different core glyph —
Envoir's continuous lowercase e/@ spiral (indigo→violet) reads *identity/mail*;
Ephor's five watch-nodes (bronze on near-black) read *oversight/brokerage*.

## Concept

*Ephor* is Greek for **overseer**: in Sparta, one of **five** ephors elected annually
to watch the state and check the kings' power — elected, term-limited, replaceable,
never sovereign, never acting alone. Ephor the product is the broker/coordinator
reference implementation of KOTVA — it brokers reach between parties, is
**content-blind** (it carries sealed traffic it cannot read), is **hired, not
depended-on**, and is **swappable**.

The mark draws that directly:

- **Five nodes, evenly placed on a ring** — the five ephors, drawn identical in size
  and colour. No node is larger, no node is centred, no node is a different hue —
  none of the five holds power alone.
- **A hollow, untouched core** — the ring the nodes sit on encloses an empty centre;
  a second, smaller ring marks that boundary explicitly so the emptiness reads as
  deliberate, not accidental. That hollow core *is* the content-blindness: the broker
  watches traffic pass through its ring without ever occupying — or seeing into —
  the centre.
- **Near-black tile, bronze accent** — the tile is a Vulos-standard near-black
  surface (not a loud brand gradient); bronze is the one warm accent against it, kept
  restrained rather than glowing.

## Palette — "Bronze"

Vulos's cool near-black surfaces stay as-is; Ephor's identity is carried entirely by
one warm accent, used sparingly, never as a full-bleed gradient tile.

| Token | Hex | Use |
|-------|-----|-----|
| **Bronze (canonical accent)** | **`#C89A56`** | the five nodes, both rings, favicon accent, console theme accent — the one value every surface should agree on |
| Bronze-ink (text-on-light) | `#8B5A2B` | wordmark fill on light backgrounds — deeper than the accent for legibility on white/cream |
| Tile near-black (top) | `#14171f` | app-tile gradient start (matches Vulos `--bg-elevated` family) |
| Tile near-black (bottom) | `#08090c` | app-tile gradient end (matches Vulos `--bg-base`) |
| OG deep umber | `#241708` | og-image background gradient end |
| OG tagline cream | `#EAD4A6` | og-image tagline text |
| OG muted warm | `#B99A76` | og-image sub-tagline text |

`#C89A56` is the single source of truth for "Ephor bronze" — the console theming
agent uses this same hex for the accent so the product mark and the product UI agree.
No teal, no purple, no Iris blue: this is a one-accent palette by design.

## Files

| File | Use |
|------|-----|
| `logo-mark.svg` | App-tile mark (near-black tile, bronze five-node ring, 240×240 viewBox, rounded tile). App icons, social avatars. |
| `logo-mono.svg` | Single-color five-node/ring mark via `currentColor` — light/dark UI, print, watermarks. |
| `favicon.svg` | Enlarged nodes, thicker core ring, thin orbit line dropped — tuned to stay legible at 16px. |
| `wordmark.svg` | Mark + "Ephor" lockup for headers/navbars. |
| `og-image.svg` | 1200×630 social card: mark, wordmark, tagline "The KOTVA broker". |
| `make-icons.mjs` | `node brand/make-icons.mjs` — rasterizes the above into `icons/` (16 through 512px, apple-touch-icon, favicon-16/32, og-image.png). Uses `rsvg-convert` if present, falls back to `npx playwright`. |
| `icons/` | Generated PNGs (not hand-maintained — regenerate via `make-icons.mjs`). |

The root `logo.png` is `logo-mark.svg` rasterized at 512×512
(`rsvg-convert -w 512 -h 512 brand/logo-mark.svg -o logo.png`).

## Type

No external fonts are embedded or required. `wordmark.svg` and `og-image.svg` set
"Ephor" with a system font stack (`system-ui, -apple-system, 'Segoe UI', Roboto,
sans-serif` / `'Helvetica Neue', Arial, sans-serif`) at a heavy weight — this keeps
the files small and dependency-free; it renders with whatever the OS's default UI
font is rather than a fixed typeface. If a locked, font-independent wordmark is ever
needed (e.g. for print), convert the `<text>` node to outlined `<path>` data with a
tool like `svg-text-to-path` and drop the `font-family`/`font-weight` attributes.

## Usage

- Keep clear space ≈ the tile corner radius around the mark.
- Don't recolor the bronze accent, stretch, skew, or add effects. Use `logo-mono.svg`
  when one flat color is needed.
- Don't fill the centre. The hollow core is the whole point — it reads as
  content-blindness. Don't add a sixth node, a centred dot, or anything that
  touches the middle.
- Keep all five nodes the same size and colour. No node is more important than the
  others — that egalitarianism is the concept.
- The mark scales down cleanly by simplification, not just shrinking: `favicon.svg`
  drops the thin faint orbit line (invisible below ~48px anyway), enlarges the five
  nodes, and thickens the core ring into a bold stroke so the "ring around a hole"
  reading survives all the way down to 16px.
