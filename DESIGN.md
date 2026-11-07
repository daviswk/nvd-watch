---
name: NVD Watch
description: A highlights page over a report body. White report stock, one deep teal ink, serif body with a sans for labels and tables.
colors:
  ink: "#1d4e5f"
  ink-deep: "#153a47"
  ink-tint: "#e6eef1"
  band: "#1d4e5f"
  on-band: "#ffffff"
  text: "#1f2328"
  text-2: "#4a4f55"
  rule: "#d8d2c8"
  rule-strong: "#1f2328"
  paper: "#ffffff"
  paper-2: "#f7f5f1"
  focus: "#b8471b"
typography:
  display:
    fontFamily: "Source Serif 4, Georgia, Times New Roman, serif"
    fontSize: "clamp(3.2rem, 7vw, 5rem)"
    fontWeight: 600
    lineHeight: 0.95
    letterSpacing: "-0.02em"
  headline:
    fontFamily: "Source Serif 4, Georgia, Times New Roman, serif"
    fontSize: "clamp(1.5rem, 2.8vw, 2.2rem)"
    fontWeight: 600
    lineHeight: 1.15
  title:
    fontFamily: "Public Sans, Helvetica Neue, Arial, sans-serif"
    fontSize: "1.6rem"
    fontWeight: 700
    letterSpacing: "-0.01em"
  title-sm:
    fontFamily: "Public Sans, Helvetica Neue, Arial, sans-serif"
    fontSize: "1.05rem"
    fontWeight: 700
  lede:
    fontFamily: "Source Serif 4, Georgia, Times New Roman, serif"
    fontSize: "1.2rem"
    fontWeight: 400
    lineHeight: 1.4
  body:
    fontFamily: "Source Serif 4, Georgia, Times New Roman, serif"
    fontSize: "1.0625rem"
    fontWeight: 400
    lineHeight: 1.55
  label:
    fontFamily: "Public Sans, Helvetica Neue, Arial, sans-serif"
    fontSize: "0.9rem"
    fontWeight: 700
    letterSpacing: "0.01em"
  table:
    fontFamily: "Public Sans, Helvetica Neue, Arial, sans-serif"
    fontSize: "0.92rem"
    fontWeight: 400
  column-head:
    fontFamily: "Public Sans, Helvetica Neue, Arial, sans-serif"
    fontSize: "0.78rem"
    fontWeight: 700
    letterSpacing: "0.04em"
  note:
    fontFamily: "Public Sans, Helvetica Neue, Arial, sans-serif"
    fontSize: "0.85rem"
    fontWeight: 400
rounded:
  none: "0"
spacing:
  xs: "6px"
  sm: "10px"
  md: "14px"
  lg: "24px"
  xl: "32px"
  section: "48px"
  gutter: "24px"
  max: "1120px"
  measure: "68ch"
components:
  button-primary:
    backgroundColor: "{colors.on-band}"
    textColor: "{colors.band}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: "11px 16px"
  button-primary-hover:
    backgroundColor: "#f0f5f7"
    textColor: "{colors.band}"
  button-outline:
    backgroundColor: "transparent"
    textColor: "{colors.on-band}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: "11px 16px"
  button-outline-hover:
    backgroundColor: "rgba(255,255,255,0.14)"
    textColor: "{colors.on-band}"
  button-text:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    typography: "{typography.note}"
    padding: "0"
  input-number:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.text}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: "9px 10px"
    width: "180px"
  segment:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.text}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: "9px 14px"
  segment-checked:
    backgroundColor: "{colors.band}"
    textColor: "{colors.on-band}"
  band:
    backgroundColor: "{colors.band}"
    textColor: "{colors.on-band}"
    padding: "28px 24px 24px"
  notice:
    backgroundColor: "{colors.ink-tint}"
    textColor: "{colors.text}"
    typography: "{typography.label}"
    padding: "10px 24px"
  cite:
    backgroundColor: "{colors.paper-2}"
    textColor: "{colors.text}"
    padding: "18px 20px"
  vendor-marker:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.text-2}"
    padding: "1px 5px"
---

# Design System: NVD Watch

## Overview

**Creative North Star: "The Highlights Page"**

NVD Watch is a government-report highlights page rendered for the web: a single identity band carries the title, the week, and two actions; under it a slim section index; then a two-column highlights grid where one finding leads at display scale with its definition and source beside it. The report body follows in four numbered sections, then frozen definitions and a sources list. The page reads top to bottom like a printed document, and the print stylesheet is a first-class rendering, not an afterthought.

The material is white report stock. One deep teal ink does all the colour work: it fills the band, sets the finding numerals, draws the rule under highlight headings, colours links and the chart bars, and fills checked controls and text selection. Body text is near-black, secondary text is a dark grey, and structure is carried entirely by hairline rules in a warm grey and 2px rules in the text colour. There are no cards, tiles, shadows, gradients, or rounded corners. Density is that of a well-set report: a 68ch measure, generous section padding, and tables that sit flush to the left column edge.

The page refuses two things by contract and by build: the KPI-tile dashboard and the dark cyber console. No dark scheme exists (`color-scheme: light`); no alarm colours exist; the one warm hue on the page (`focus`) is reserved for focus rings and never appears as text or fill.

**Key Characteristics:**
- One identity ink on white stock; a second hue only for focus indication.
- Serif body (Source Serif 4) with a sans (Public Sans) for everything that labels, tabulates, or acts.
- Structure by rule, never by surface: 1px warm hairlines for rows, 2px near-black rules for table heads, totals, and the simulator's top edge.
- Run-in numbered section headings; the number is set in secondary grey at regular weight ahead of the bold title.
- Rectangular geometry throughout; the only circles are the 12px timeline markers.
- Prints as a report: band flattens to black type over a 3pt black rule, actions and index disappear, chart bars go black.

## Colors

A single deep teal ink on white paper, with near-black text, two greys, and a warm hairline; one burnt-orange hue reserved for focus rings.

### Primary
- **Deep Teal Ink** (`ink`): the only coloured ink. Finding numerals, highlight headings and the 2px rule beneath them, section titles, links, the section-index numerals and hover underline, chart bars and value labels, the timeline spine and markers, the metrics counter, bold run-ins inside findings and the simulator result, the "Assumption" prefix, and the reset text-button.
- **Deep Teal, Pressed** (`ink-deep`): link hover only, paired with a thicker (2px) underline.
- **Teal Wash** (`ink-tint`): one flat tint, used only as the background of the stale-data notice under the section index. It is not a card fill.
- **Band Fill** (`band`) and **On Band** (`on-band`): the filled surfaces. The identity band, the checked segment in the simulator's radio group, the KEV marker on the timeline, and `::selection`. `band` is the same value as `ink` by design; keep them separate tokens so filled surfaces can be reasoned about apart from inked text.

### Neutral
- **Report Black** (`text`): body text, the simulator input border, data-table captions, and (as `rule-strong`) every 2px structural rule.
- **Secondary Grey** (`text-2`): section-index links at rest, section numbers, small print under findings, table column heads, footnotes, notes and assumptions, vendor markers, footer text, and the stacked-table `data-label` prefix.
- **Warm Hairline** (`rule`): every 1px row and section divider, the section-index bottom edge, the vendor marker's border.
- **Strong Rule** (`rule-strong`): the 2px rule under table heads and above totals, the simulator's top rule, input and segmented-control borders. Same value as `text`.
- **Report Stock** (`paper`): page background, the section index background, inputs, unchecked segments, timeline markers.
- **Second Stock** (`paper-2`): the one flat warm tint, used only for the citation block.

### Focus
- **Burnt Orange** (`focus`): 3px solid outline, 2px offset, on every `:focus-visible`; inset by 3px inside the segmented control. Never text, never fill.

### Named Rules
**The One Ink Rule.** Teal is the only colour that may carry meaning. If a new element needs emphasis, it gets teal, weight, or a rule; it never gets a second hue.

**The Focus-Only Rule.** `focus` (#b8471b) appears on focus rings and nowhere else. It is not an accent, a warning, or a link colour.

**The Flat Tint Rule.** `ink-tint` and `paper-2` are the only tinted surfaces, each used once (notice, citation block). They carry no border, radius, or shadow; a tinted surface is a flat paragraph background, not a card.

## Typography

**Display / Headline / Body Font:** Source Serif 4 (with Georgia, Times New Roman, serif); loaded from Google Fonts at weights 400 and 600 with the optical-size axis (opsz 8..60).
**Label / Table / UI Font:** Public Sans (with Helvetica Neue, Arial, sans-serif); weights 400 and 700.

**Character:** A report pairing. The serif carries the argument (headline, body, ledes, the display figure); the sans carries everything that labels, tabulates, or acts (band meta, index, headings inside the report body, table text, buttons, inputs, notes, footer). Numerals are lining and tabular everywhere (`font-variant-numeric: lining-nums tabular-nums` on `body`).

### Hierarchy
- **Display** (`display`; Source Serif 4 600, `clamp(3.2rem, 7vw, 5rem)`, line-height 0.95, tracking -0.02em, teal): the lead finding figure only. One per page.
- **Headline** (`headline`; Source Serif 4 600, `clamp(1.5rem, 2.8vw, 2.2rem)`, line-height 1.15, max 34ch, balanced): the band h1.
- **Title** (`title`; Public Sans 700, 1.6rem, tracking -0.01em, teal): report-section h2, with the run-in number set in `text-2` at weight 400 in a 1.4em slot.
- **Highlight heading** (Public Sans 700, 0.95rem, uppercase, tracking 0.02em, teal, 2px teal rule beneath): the three highlights-grid h2s. This is the only uppercase heading style.
- **Title small** (`title-sm`; Public Sans 700, 1.05rem, text colour): h3 within sections and the citation block.
- **Finding definition** (Source Serif 4 400, 1.25rem, line-height 1.3, max 30ch, balanced): the sentence beside the display figure; its `small` drops to Public Sans 0.82rem in `text-2`.
- **Lede** (`lede`; Source Serif 4 400, 1.2rem, line-height 1.4): first paragraph of each report section. The simulator result sentence is a near sibling at 1.15rem / 1.45.
- **Body** (`body`; Source Serif 4 400, 1.0625rem, line-height 1.55, max 68ch): paragraphs, list items, definitions, recommendations table cells (1rem).
- **Label** (`label`; Public Sans 700, 0.9rem, tracking 0.01em): buttons, band product line (0.95rem), form labels, legends, definition terms, timeline dates (0.82rem), metric titles (0.95rem).
- **Table** (`table`; Public Sans 400, 0.92rem; 0.85rem under 600px): data-table cells. Row heads are weight 400; the total row and captions are 700.
- **Column head** (`column-head`; Public Sans 700, 0.78rem, uppercase, tracking 0.04em, `text-2`): data-table `thead`. The recommendations table's row heads use the same treatment at 0.8rem in teal.
- **Note** (`note`; Public Sans 400, 0.85rem, `text-2`): notes, footer, section index (0.85rem), assumptions (0.8rem), table footnotes and finding small print (0.82rem), API status values (0.75rem), vendor markers (0.75rem, 700).

### Named Rules
**The Serif Argues, Sans Labels Rule.** Anything a reader is meant to read as prose or as the finding is serif; anything that names, tabulates, or operates is sans. Do not set a heading inside the report body in serif, and do not set body copy in sans.

**The One Display Rule.** The display size appears once, on the lead finding. Other figures live in tables or as bold run-ins at body size.

**The Tabular Numerals Rule.** Numbers are lining and tabular everywhere, including inputs; right-align numeric columns and never wrap them.

## Layout

A single centred column, max 1120px, with a 24px gutter, laid out as band, section index, optional notice, highlights grid, four report sections, definitions, sources, footer. Every section and metric row has an id for permalinks.

- **Band:** two-column grid (`1fr auto`), items aligned to the bottom edge, 28px top / 24px bottom padding, 24px row and 40px column gap. Actions sit right and wrap. Under 900px it stacks to one column and actions align left.
- **Section index:** sticky at the top (z-index 5), 1px warm hairline beneath, items in a row with 28px gaps and 12px vertical padding, horizontal overflow permitted. Under 600px it becomes static and wraps to two rows with 22px gaps and 8px padding so the pinned bar never covers phone content.
- **Highlights grid:** `minmax(0, 380px) minmax(0, 1fr)`, 32px row / 64px column gap, 44px top / 48px bottom padding, hairline beneath. One column with 32px gap under 900px.
- **Finding block:** `auto 1fr` grid aligned at the baseline, 8px row / 24px column gap. One column with 6px gap under 600px.
- **Report sections:** 48px top / 40px bottom padding, hairline beneath. Inside, `.two` splits `1fr 1fr` with 24px row / 56px column gap and collapses to one column under 900px. In print, each section avoids page breaks and gets 18pt padding and a 1pt grey rule.
- **Measure:** 68ch on paragraphs, list items, findings, notes, and the simulator result. Definitions and metrics lists cap at 860px; the chart at 560px.
- **Definitions:** `200px 1fr` grid with 10px row / 24px column gap; one column with 4px gap under 900px, where the term loses its own rule.
- **Simulator controls:** three equal columns with 20px row / 32px column gap; two columns under 900px; one under 600px.
- **Rhythm:** paragraph margin 14px; h3 34px above / 10px below; table rows 9–10px vertical padding; findings and metrics rows 12px; timeline items 16px below.
- **Breakpoints:** 900px (grids collapse) and 600px (phone: index static, tables stack, type steps down).

**The Stacked Table Rule.** A data table that would clip on a phone carries `.stack`. Under 600px its head is visually hidden, each row becomes a labelled block whose row head sits on a 2px rule, and each numeric cell becomes a flex row with its column name on the left from `data-label` and the value right-aligned. Every numeric cell in a `.stack` table must carry `data-label`.

## Elevation & Depth

The system is flat. No `box-shadow`, no gradient, no translucency on surfaces (the one `rgba` is the outline button's hover wash on the band). Depth is conveyed by rules and by two flat tints: the teal band at the top, and the paper-2 citation block and ink-tint notice as low, bordered-by-nothing paragraph backgrounds. The sticky section index sits over content with a hairline, not a shadow.

### Named Rules
**The No-Shadow Rule.** Nothing on the page casts a shadow or lifts. If a new element must separate from the page, it gets a rule or a flat tint.

## Shapes

Rectangular. `border-radius` is 0 on every surface, button, input, segment, table, and tinted block. Borders are the form language: 2px solid borders on buttons (on-band white), number inputs, and the segmented control (rule-strong), with 2px internal dividers between segments; 1px hairlines for rows and the vendor marker. The sole circles are the timeline's 12px markers (paper fill, 2px teal border; the KEV event is filled teal), and the sole clipping is the SVG chart's own viewBox. Inline SVG icons in buttons are 16px, stroke 2, round caps and joins, `currentColor`.

## Components

### Buttons
Rectangular, bold sans, inline-flex with an 8px gap for a 16px icon. Both variants live on the band and are hidden in print.
- **Shape:** square corners (0), 2px solid border in `on-band`.
- **Primary (filled):** white fill, teal text, padding 11px 16px; hover fill shifts to a faint teal-white (#f0f5f7). Used once, for Copy citation; its label swaps to "Copied" or "Select and copy below" for 2.2s.
- **Outline:** transparent fill, white text and border; hover adds a 14% white wash. Used for the brief link.
- **Text button:** the simulator's reset: no border or fill, teal, underlined, note size, zero padding.
- **Focus:** the global 3px `focus` outline, 2px offset.

### Inputs / Fields
- **Number input:** sans, tabular numerals, 2px `rule-strong` border, paper fill, text colour, padding 9px 10px, full width to a 180px max; inherits body size. Label above in bold sans 0.9rem with a 6px gap; an `.assumption` line beneath in 0.8rem `text-2`, prefixed by a bold teal "Assumption".
- **Segmented radio group:** a `max-content` row inside one 2px `rule-strong` border, segments padded 9px 14px with 2px dividers, bold sans; the native radio is visually hidden over the segment. Checked segment fills `band` with `on-band` text. Focus outline is inset by 3px so it stays inside the frame.
- **Error / Disabled:** none defined; values are clamped in script.

### Navigation (section index)
Sans 0.85rem list in a row under the band; links in `text-2` with no underline and a transparent 2px bottom border that turns teal on hover along with the text. Section numbers are bold teal with a 6px gap. Sticky with a hairline below above 600px; static and wrapping under. No active-state styling is implemented.

### Identity band
Teal fill, white type. Product line in bold sans 0.95rem with the tagline at weight 400 and 90% opacity; serif headline; meta line in sans 0.9rem at 92% opacity. Prints as black type on white over a 3pt black rule, actions removed.

### Highlights grid
Left column headed by an uppercase teal sans heading on a 2px teal rule; three serif paragraphs and a sans source line (0.82rem, `text-2`, 22px above). Right column: the finding block, a ruled findings list, and the recommendations table.

### Finding block
The display figure beside a 1.25rem serif definition with `small` sans print beneath. Baseline-aligned; stacks on phones.

### Ruled lists
- **Findings:** unbulleted, 12px vertical padding, 1px hairline above each row, bold run-ins in teal.
- **Metrics:** numbered by CSS counter in bold teal sans 1.1rem in a 2.2em slot, 12px padding, hairline above, title in bold sans 0.95rem on its own line.
- **Timeline:** 1px teal left spine, items padded 4px 0 16px 22px, 12px circular markers straddling the spine, date in bold teal sans 0.82rem on its own line. The `.kev` item has a filled marker.

### Tables
- **Recommendations (`.recs`):** serif 1rem, collapsed, row heads in uppercase sans 0.8rem teal in a 110px column (84px under 600px), hairline above every row, 10px padding.
- **Data (`.data`):** sans 0.92rem, left caption in bold 0.95rem, column heads uppercase 0.78rem `text-2` on a 2px `rule-strong` bottom rule, body rows on 1px hairlines with 9px padding, `.num` cells right-aligned and non-wrapping, `.total` row bold on a 2px rule, footnote in 0.82rem `text-2` with no border. `.api` sub-label in 0.75rem `text-2` on its own line. `.stack` variant stacks under 600px (see Layout).

### Chart (`.chart`)
Inline SVG, max 560px, sans. Bars fill teal, value labels bold teal 14px, year labels 13px text colour, a 1px `rule-strong` axis. Carries `<title>` and `<desc>`; a `.note` figcaption cites the source. Bars print black.

### Notice and citation block
- **Notice:** sans 0.9rem on `ink-tint`, padded 10px by the gutter, no margin; `role="status"`. Prints white with a 1pt grey border.
- **Citation (`.cite`):** `paper-2` block padded 18px 20px, max 860px, h3 title, sans 0.9rem paragraph with `user-select: all` so one click selects the citation.

### Vendor marker
Inline sans 0.75rem bold `text-2` chip with a 1px hairline border, padding 1px 5px, 6px left margin, after a vendor or disputed source.

## Do's and Don'ts

### Do:
- **Do** use teal (`ink`) for every emphasis that needs colour: numerals, headings, links, bars, run-ins, counters.
- **Do** structure with rules: 1px `rule` between rows and sections, 2px `rule-strong` under table heads, above totals, and around inputs.
- **Do** keep the serif for prose and the finding, and Public Sans for labels, tables, controls, notes, and in-body headings.
- **Do** keep the display size to the single lead finding and set it in Source Serif 4 600 with tight leading.
- **Do** give every `.stack` numeric cell a `data-label` so it survives the phone layout.
- **Do** keep the 68ch measure on prose and right-align tabular numbers.
- **Do** supply `<title>` and `<desc>` on any SVG chart and a `.note` caption naming the source.
- **Do** make every surface print: flatten fills to black type on white and hide actions.

### Don't:
- **Don't** introduce a second hue, alarm colours, or a dark scheme; the page is `color-scheme: light` only.
- **Don't** use `focus` (#b8471b) as text, fill, or accent.
- **Don't** add border-radius, box-shadow, gradients, or card surfaces; tints are flat paragraph backgrounds used once each.
- **Don't** render findings as KPI tiles; a finding is a figure with its definition and source beside it, or a ruled row.
- **Don't** set in-body headings in serif or body copy in sans.
- **Don't** add a second uppercase heading style; uppercase is reserved for the highlights headings and table column heads.
