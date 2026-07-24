# Ephor brand

The Ephor mark is **a comma drawn so it reads as a lowercase "e"** — the product's
initial and a punctuation mark at once. One continuous bronze gesture: the bowl and
crossbar make the *e*; the *e*'s lower terminal keeps going, curling down into the
comma's tail. Hold it as a letter and it says *Ephor*; hold it as punctuation and it
is a comma — a small mark that sits between things without being the thing.

Ephor is a **sibling** of the [Envoir](../../envoir) mark, not a clone: same build
quality and lockup conventions (rounded-square tile, mono variant via `currentColor`,
wordmark/og-image pattern), deliberately different hue and a different core glyph —
Envoir's continuous lowercase e/@ spiral (indigo→violet) reads *identity/mail*;
Ephor's comma-e (bronze on near-black) reads *the mark between, the overseer*.

## Concept

*Ephor* is Greek for **overseer**: in Sparta, one of five ephors elected annually
to watch the state and check the kings' power — elected, term-limited, replaceable,
never sovereign. Ephor the product is the broker/coordinator reference implementation
of KOTVA — it brokers reach between parties, is **content-blind** (it carries sealed
traffic it cannot read), is **hired, not depended-on**, and is **swappable**.

The mark draws that directly:

- **A comma that reads as an "e"** — the double reading is the whole idea. The letter
  names the product; the comma says what it *does*. A comma is the mark that stands
  between two clauses, joining them without belonging to either — exactly a broker's
  place between two parties.
- **One open, continuous stroke** — the bowl of the *e* is left open at its lower
  right (the aperture), and the stroke exits there into the tail rather than closing
  on itself. Nothing is sealed shut; the mark passes traffic through rather than
  enclosing it. Read that aperture as the content-blindness — the form carries but
  never contains.
- **Near-black tile, bronze accent** — the tile is a Vulos-standard near-black
  surface (not a loud brand gradient); bronze is the one warm accent against it, kept
  restrained rather than glowing.

## Palette — "Bronze"

Vulos's cool near-black surfaces stay as-is; Ephor's identity is carried entirely by
one warm accent, used sparingly, never as a full-bleed gradient tile.

| Token | Hex | Use |
|-------|-----|-----|
| **Bronze (canonical accent)** | **`#C89A56`** | the comma-e glyph, favicon accent, console theme accent — the one value every surface should agree on |
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
| `logo-mark.svg` | App-tile mark (near-black tile, bronze comma-e, 128×128 viewBox, rounded tile). App icons, social avatars. |
| `logo-mono.svg` | Single-color comma-e via `currentColor` — light/dark UI, print, watermarks. |
| `favicon.svg` | Heavier stroke, larger glyph, shorter tail — tuned to stay legible at 16px. |
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
- Keep the aperture open. The gap at the lower-right of the bowl, where the stroke
  exits into the tail, is deliberate — it is what makes the *e* read as a comma and
  what carries the content-blind meaning. Don't close the bowl into a solid ring.
- Preserve the double reading. Don't straighten the tail into a plain descender (it
  stops being a comma) and don't shorten the crossbar until the *e* is unreadable.
- The mark scales down by simplification, not just shrinking: `favicon.svg` uses a
  heavier stroke, a larger glyph, and a shorter tail (a long thin tail disappears
  first at small sizes) so the comma-e still reads at 16px.
