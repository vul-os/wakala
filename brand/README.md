# Ephor brand

The Ephor mark is **a comma whose notch opens it into a lowercase "e"** — the
product's initial and a punctuation mark at once. One solid form: a bold comma,
with a single wedge cut out of its shoulder; that cut is the *e*'s aperture, and
the counter it leaves is the *e*'s eye. Hold it as a letter and it says *Ephor*;
hold it as punctuation and it is a comma — a small mark that sits between things
without being the thing.

There are two marks:

- **`ephor.svg`** — the mark. This is the logo, used everywhere: app icons,
  favicon, the console's sidebar lockup, product listings.
- **`ephor-combined.svg`** — the paired mark: two commas turned to face each
  other, one solid and one muted. Reserved for the console's topbar and footer.
  Two parties, and the mark standing between them — the broker's shape.

Both are drawn with `fill="currentColor"` and are sized by height (the single
mark is portrait, the paired mark landscape). That is deliberate: a fixed fill
cannot work across this product's two canvases — white disappears on the
warm-paper light theme and near-black disappears on the `#0c0c0c` dark theme.
Set `color` on the parent and the mark follows the theme. The paired mark keeps
its two-tone relationship by giving the trailing comma `opacity: 0.5` rather
than a second hardcoded grey, so the pairing survives on any surface.

Ephor is a **sibling** of the [Envoir](../../envoir) mark, not a clone: same build
quality and lockup conventions (rounded-square tile, mono variant via `currentColor`,
wordmark/og-image pattern), deliberately different hue and a different core glyph —
Envoir's continuous lowercase e/@ spiral (indigo→violet) reads *identity/mail*;
Ephor's notched comma (bronze on near-black) reads *the mark between, the overseer*.

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
- **The notch is the point** — the wedge cut from the comma's shoulder is what
  turns it into a letter, and it leaves the form open rather than sealed. The mark
  carries without containing; read that opening as the content-blindness.
- **The paired mark** — two commas facing each other, solid and muted. It is the
  same glyph twice, standing on either side of an empty middle: the two parties,
  and the broker that never occupies the space between them.
- **Near-black tile, bronze accent** — the tile is a Vulos-standard near-black
  surface (not a loud brand gradient); bronze is the one warm accent against it, kept
  restrained rather than glowing.

## Palette — "Bronze"

Vulos's cool near-black surfaces stay as-is; Ephor's identity is carried entirely by
one warm accent, used sparingly, never as a full-bleed gradient tile.

| Token | Hex | Use |
|-------|-----|-----|
| **Bronze (canonical accent)** | **`#C89A56`** | the mark, favicon accent, console theme accent — the one value every surface should agree on |
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
| `ephor.svg` | **The mark.** Portrait, `currentColor`, no tile — the source the assets below are built from, and what the console inlines. |
| `ephor-combined.svg` | **The paired mark.** Landscape, `currentColor` with the trailing comma at `opacity: 0.5`. Console topbar + footer only. |
| `logo-mark.svg` | App-tile mark (near-black tile, bronze comma, 128×128 viewBox, rounded tile). App icons, social avatars. |
| `logo-mono.svg` | Single-colour mark via `currentColor` — light/dark UI, print, watermarks. |
| `favicon.svg` | Same tile, glyph enlarged within it so the notch survives to 16px. |
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
- Keep the notch. The wedge cut from the comma's shoulder is the whole mark — it is
  what makes the form read as an *e* and what carries the content-blind meaning.
  Don't fill it in, don't shrink it until it closes.
- Preserve the double reading. Don't straighten the tail into a plain descender —
  it stops being a comma.
- Size by height, never by width. The single mark is portrait (72×92) and the paired
  mark landscape (130×92); forcing either into a square box squashes it.
- Don't hardcode a fill. Both masters are `currentColor` so one file works on the
  near-black and the warm-paper canvas — set `color` on the parent instead.
- The mark shrinks well because it is one solid shape, but check the notch at 16px
  after any change: `favicon.svg` enlarges the glyph within the tile for exactly
  this reason. Rasterise and look, don't assume.
