# AI DAST WebUI Design System

## 1. Atmosphere & Identity

AI DAST is a restrained local security workspace: calm enough for sustained
operator use, explicit about trust boundaries, and dense only where the data
requires it. Its signature is the persistent live-activity rail, which keeps
connection state, scan progress, and chronological events visible without
competing with the primary task.

## 2. Color

### Palette

| Role | Token | Light | Dark | Usage |
| --- | --- | --- | --- | --- |
| Surface / primary | `--bg` | `#eef3f0` | `#101419` | Workspace background |
| Surface / panel | `--panel` | `#ffffff` | `#161c23` | Cards, forms, activity controls |
| Surface / soft | `--soft` | `#e6f0e9` | `#202e2a` | Selected and emphasized regions |
| Border / default | `--line` | `#d5dfd9` | `#29313a` | Dividers and outlines |
| Text / primary | `--text` | `#17221d` | `#e3e9ed` | Headings and body copy |
| Text / secondary | `--muted` | `#607068` | `#9fabb6` | Metadata and supporting copy |
| Accent / primary | `--accent` | `#377b55` | `#a9d7bb` | Actions, focus, live progress |
| Status / warning | `--amber` | `#916b24` | `#dfbe7f` | Caution and demo state |

### Rules

- Green communicates an active or verified state, not decoration.
- Amber communicates caution or synthetic/demo state.
- Red is reserved for errors, rejected decisions, and critical findings.
- Dark-theme secondary text targets at least 7:1 contrast where practical
  because the activity stream uses small monospace metadata.
- New colors must be introduced here before component CSS uses them.

## 3. Typography

### Scale

| Level | Size | Weight | Line height | Usage |
| --- | --- | --- | --- | --- |
| Page title | `30px` | 600 | 1.2 | Page heading |
| Section title | `16px` | 600 | 1.35 | Panel heading |
| Card title | `15px` | 600 | 1.4 | Local grouping |
| Body | `14px` | 400 | 1.55 | Default interface copy |
| Body / small | `13px` | 400-600 | 1.5 | Supporting text and controls |
| Caption | `12px` | 500 | 1.45 | Labels and metadata |
| Overline | `10px` | 600 | 1.3 | Eyebrows and section markers |
| Log body | `12.5px` | 400 | 1.75 | Live event messages |
| Log metadata | `11px` | 500 | 1.4 | Time, stage, and stream markers |

### Font stacks

- Primary: `Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`
- Monospace: `"SFMono-Regular", Consolas, "Liberation Mono", monospace`

### Rules

- Interface text does not fall below `11px`. Only the short navigational
  overlines `.eyebrow`, `.heading-tag`, `.nav-label`, and `.brand small` may
  use `10px`.
- Operational body and explanatory copy does not fall below `12px`.
- Log message copy remains monospace but is never smaller than `12.5px`.
- Mobile breakpoints never reduce a selector below its desktop font size.
- Data-heavy numbers use tabular figures.
- Uppercase labels are limited to short metadata and use increased tracking.

## 4. Spacing & Layout

### Base unit

Spacing follows a 4px base with practical steps of 4, 8, 12, 16, 20, 24,
32, and 40px.

### Shell

- Desktop: fixed side navigation, fluid content, persistent activity rail.
- The activity rail owns its log scroll; the document owns main-content
  scroll. Controls and footer remain outside the log scroll region.
- At wide desktop sizes the activity rail is `380-400px`, preserving readable
  log lines and filter controls.
- At `900px` and below the activity rail becomes a fixed, collapsible bottom
  sheet so live state is reachable without scrolling through page content.
- At `660px` and below the sheet sits above the 64px bottom navigation.
- Primary content must reflow without horizontal scrolling at `390px`.

## 5. Components

### Panel

- **Structure**: section, heading cluster, optional action, body.
- **Variants**: standard, notice, error, empty.
- **States**: default, hover where actionable, focus, empty, error.
- **Accessibility**: semantic section headings and visible focus.
- **Layout**: vertical stack; the document owns scrolling.

### Status badge

- **Structure**: status dot plus concise label.
- **Variants**: live/success, demo/warning, error/critical, neutral.
- **States**: static status; no decorative animation.
- **Accessibility**: status is expressed in text as well as color.
- **Layout**: inline cluster.

### Metric card

- **Structure**: label/icon row, tabular value, contextual note.
- **Variants**: green, blue, amber, purple.
- **States**: static until a real navigation action is assigned.
- **Accessibility**: color never carries the value alone.
- **Layout**: responsive grid; values do not dominate actionable content.

### Activity rail

- **Structure**: header, source status, stage progress, search and filters,
  follow control, scrollable event stream, redaction footer.
- **Variants**: desktop rail, tablet sheet, mobile sheet, collapsed.
- **States**: live, demo, reconnecting, offline, following, paused, empty.
- **Accessibility**: named aside, keyboard-scrollable stream, labelled filters,
  text status in addition to dots, and a labelled collapse control.
- **Motion**: no decorative motion; event arrival relies on scroll position and
  visual emphasis.
- **Layout**: fixed controls around one bounded `.log-stream` scroll owner.

### Log entry

- **Structure**: timestamp, stage, level indicator, message.
- **Variants**: info, success, warning, error.
- **States**: default and newest-event emphasis.
- **Accessibility**: readable contrast, text level available to assistive
  technology, and wrapping for unbroken data.
- **Layout**: chronological vertical stack.

## 6. Motion & Interaction

| Type | Duration | Easing | Usage |
| --- | --- | --- | --- |
| Micro | `150ms` | ease-out | Hover and press feedback |
| Standard | `200-300ms` | ease-in-out | Sheet or panel state changes |

- Motion only communicates interaction or state.
- Layout properties are not animated.
- `prefers-reduced-motion: reduce` disables non-essential transitions.
- Pause stops auto-follow only; event ingestion continues.

## 7. Depth & Surface

The primary strategy is **borders plus tonal shift**. Panels separate through
one-pixel borders and adjacent dark or light surface tones. Shadows are
reserved for true overlays such as dialogs and the mobile activity sheet.
Cards do not receive decorative shadows.

## 8. Accessibility Constraints & Accepted Debt

### Constraints

- Target WCAG 2.2 AA; dark activity metadata aims for 7:1 contrast.
- Every interactive control has a visible focus indicator.
- Status never depends on color alone.
- Touch targets are at least 38px; primary actions target 40px or more.
- Korean and English copy must wrap without clipping or orphaned controls.
- The mobile activity sheet must remain collapsible and must not cover the
  bottom navigation.

### Accepted debt

| Item | Location | Why accepted | Exit |
| --- | --- | --- | --- |
| Connection vocabulary is rendered by three existing call sites | `src/App.tsx` | This pass is intentionally CSS-first and avoids restructuring the oversized application component | Extract one shared status component during the planned App decomposition |
| Log timestamps show clock time without day boundaries | `src/App.tsx` | Requires event presentation logic, not visual styling | Add date rollover markers when multi-day scan UX is implemented |
| Several legacy component colors and spacings remain literal values | `src/styles.css` | Full token migration would exceed this focused readability change | Consolidate opportunistically when each component is next changed |
