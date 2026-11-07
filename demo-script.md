# Pyzex Guard — 2-Minute Product Demo Script & Motion Storyboard

**Total duration: exactly 120 seconds.** · Format: 1920×1080, 25 fps (3000 frames).
**Audio:** Indonesian voice-over (technical English terms kept), licensed electronic score.
**Rendering status of this document: RENDER-READY STORYBOARD + PRODUCTION INSTRUCTIONS.**
No MP4 is claimed to exist yet — see §9 for rendering paths.

---

## 0. Concept — one metaphor, no arbitrary cuts

**Visual metaphor:** *an exposed secret becomes a protected, structured, auditable workflow.*

One artifact — a credential line of monospace text — survives the entire film
by **transforming**, never by cutting away:

```text
credential line ─▶ redaction token ─▶ workflow connection ─▶ policy boundary ─▶ audit record
```

Every scene grows out of the previous one: if an element exits the frame, it
morphs into the next scene's stage geometry. This is a deliberate reference to
Prompt Motion's showreel structure (beat-locked scene families, continuous
geometry, kinetic typography) — rebuilt as an original Pyzex Guard concept, not
a template imitation.

**Motion language:** exponential/spring easing, 200–450 ms moves, camera
push-ins instead of zoom cuts, subtle directional motion blur on fast morphs
only, one typeface family per role (Inter for narrative, JetBrains Mono for
data), palette locked to obsidian `#0A0A0A` / surface `#141414` / emerald
`#10B981` / crimson `#EF4444` / white `#F5F5F5` / gray `#8B8B8B`.

**Forbidden:** particle explosions, lens flares, RGB split, camera shake,
generic gradient waves, bouncy default easing, hard cuts, fake terminal
glyphs, emoji as UI.

---

## 1. Exact timeline (mm:ss / frames @ 25 fps)

### ACT 1 — THE HOOK · 00:00–00:25 · frames 0–625

| Time | Frame | Screen | Motion & camera |
| --- | --- | --- | --- |
| 00:00–00:04 | 0–100 | Obsidian canvas; a single cursor caret blinks. Kinetic type assembles: `config.production.env` | Camera drifts in 3%; letters snap in with 8 px stagger |
| 00:04–00:10 | 100–250 | A git diff draws itself, one line per half-second; comfortable leading, gray `+/-` rails | Slow top-to-bottom pan, as if the camera rides the file |
| 00:10–00:17 | 250–425 | One line brightens: `TENCENT_SECRET_ID=AKID…` — the value **heats** from white → crimson; a thin crimson scanline sweeps the full frame width, once | Camera pushes toward the line (z 1.0→1.18, 700 ms, expo-out); motion blur 4 px directional, vertical |
| 00:17–00:22 | 425–550 | The crimson value **collapses into a redaction token**: `[REDACTED:CLOUD_SECRET_ID]` — an emerald-outlined chip; the surrounding diff dims to 30% | Value scales down & morphs width into the chip (spring, 380 ms, slight overshoot 4%) |
| 00:22–00:25 | 550–625 | The chip drops one level "into" a workflow rail that extends left-right beyond frame edges; title sets: **PYZEX GUARD — Catch the leak. Understand the risk. Fix it before it ships.** | Chip lands with 2-frame settle; title types in mono caps |

**VO (00:00–00:25):**
"Di alur kerja sehari-hari, satu baris di git diff bisa memuat kredensial cloud yang sah. Tidak perlu penyerang yang canggih — cukup satu commit yang terlewat. Pyzex Guard menangkap kebocoran itu sebelum terjadi: nilai rahasia disamarkan secara lokal, sebelum data menyentuh AI."

**On-screen text:** `TENCENT_SECRET_ID=[REDACTED:CLOUD_SECRET_ID]` · `LOCAL REDACTION BEFORE AI`
**Morph out:** the token chip becomes the first node of the product walkthrough's workflow rail.

**SFX:** low sub swell (40 Hz) under 00:10–00:17; single "lock" click at the token collapse; music side-chains 3 dB.

### ACT 2 — LIVE PRODUCT WALKTHROUGH · 00:25–01:15 · frames 625–1875

*All product shots are REAL captures of the running dashboard (see §7). The provider indicator in the video reads DEMO/MOCK per the project's honest-labeling rule.*

| Time | Frame | Action (real UI) | Motion & camera |
| --- | --- | --- | --- |
| 00:25–00:31 | 625–775 | Dashboard fades in already loaded (preset 1 active). Cursor selects **Leaked Tencent Cloud Secret & Insecure DB Config** | 220 ms cross-dissolve from the rail (the rail's geometry aligns to the pipeline strip — the morph sells continuity); camera at 1.0 |
| 00:31–00:38 | 775–950 | **Local secret detection**: privacy preview counter ticks `0 → 4`; detection chips pop in (`CLOUD_SECRET_ID`, `CLOUD_SECRET_KEY`, `DATABASE_CONNECTION_STRING`, `JWT_SECRET`) | Chips scale 0.92→1 with 60 ms stagger; counter uses a mechanical flip |
| 00:38–00:47 | 950–1175 | **Reveal the privacy preview / masked payload**: camera tilts to the sanitized payload panel; `[REDACTED:*]` tokens subtly breathe once | Slow push to 1.12 on the panel; tokens get a 1 px emerald edge-glint (single pass, 400 ms) |
| 00:47–00:52 | 1175–1300 | **Trigger Agent Triage** — button pressed (real cursor), pipeline strip activates | Button depresses 2 px; the eight stage dots ignite left→right, 70 ms stagger, emerald fill |
| 00:52–01:00 | 1300–1500 | **Workflow progression**: stage labels light with real per-stage ms timings; result lands | The moment the response lands, the findings panel slides up 12 px & fades in 240 ms |
| 01:00–01:08 | 1500–1700 | **Findings**: risk gauge sweeps to its measured value; severity chip sets; first finding card highlights: redacted evidence, confidence bar, ROTATE CREDENTIAL tag | Gauge arc animates 600 ms expo-out; camera drifts across the card 8 px left |
| 01:08–01:15 | 1700–1875 | **Remediation + copy patch**: unified diff colors in (`+` emerald / `−` crimson); COPY PATCH pressed → label flips to COPIED; amber approval banner: HUMAN APPROVAL REQUIRED | Diff rows cascade 20 ms stagger; the banner's left rail draws top→bottom in 300 ms |

**VO (00:25–01:15):**
"Ini dasbor aslinya. Saya muat konfigurasi demo — empat nilai sensitif terdeteksi secara lokal, dalam hitungan milidetik. Ini bagian terpenting: pratinjau privasi. Payload inilah yang benar-benar keluar ke AI — sudah tersamarkan, strukturnya utuh. Sekarang saya jalankan agent triage. Delapan tahap workflow berjalan dengan timing nyata per tahap. Hasilnya: temuan per kredensial, bukti tersamarkan, tingkat keyakinan, dan indeks risiko yang dihitung deterministik oleh server — bukan opini model. Dan usulan perbaikan: unified diff siap salin. Catatan rapat: patch ini hanya usulan — persetujuan manusia wajib, dan agent tidak pernah menerapkan perubahan."

**On-screen text:** `LOCAL DETECTION: 4 VALUES` · `WHAT THE AI RECEIVES` · `DETERMINISTIC RISK INDEX` · `PROPOSAL ONLY — HUMAN APPROVAL REQUIRED`
**Morph out:** the COPIED chip flies left and docks as the first node of Act 3's architecture line.

### ACT 3 — ARCHITECTURE · 01:15–01:45 · frames 1875–2625

| Time | Frame | Screen | Motion & camera |
| --- | --- | --- | --- |
| 01:15–01:22 | 1875–2050 | 2D architecture rail slides from the docked chip: `PYSCAN → LOCAL REDACTION → AI CORE → PYGUARD → NEON POSTGRES`; nodes are flat plates, thin connectors | Camera pulls back 1.0→0.94; rail assembles 90 ms per node |
| 01:22–01:31 | 2050–2275 | **The privacy boundary**: the segment between LOCAL REDACTION and AI CORE lifts into a subtle 3D slab (rotateY ≈ 14°); crimson boundary band stands upright; label `RAW VALUES NEVER CROSS` | Camera arcs 20° around the slab (2D→3D moment, 700 ms, expo-inOut); depth-of-field: nodes beyond the slab soften 15% |
| 01:31–01:38 | 2275–2450 | The sanitized payload chip from Act 1 re-enters and **crosses** the boundary — now a flat, typed placeholder; inside the AI CORE plate, a compact GLM-5.3-Flash label with `SumoPod · OpenAI-compatible` | Chip crossing = single 420 ms morph; on landing, the core plate's edge ticks emerald once |
| 01:38–01:45 | 2450–2625 | Output side: amber `POLICY GATE` band raises; the payload becomes an audit row that files into a NEON POSTGRES ledger stack; row visibly shows `[REDACTED:…]` | Row slides into the stack with 2-frame bounce; ledger acquires one row per beat (3 beats) |

**VO (01:15–01:45):**
"Ini mengapa aman. Sebelum AI: PYSCAN dan redaksi lokal — deterministik, berjalan penuh di server aplikasi. Satu-satunya komponen probabilistik adalah inti AI di tengah: GLM-5.3-Flash lewat endpoint OpenAI-compatible bawaan sponsor, SumoPod — dikonfigurasi lewat environment variable, jadi provider bisa diganti tanpa mengubah logika. Setelah AI: gerbang kebijakan PYGUARD — validasi skema ketat, saringan kebocoran, dan konfirmasi manusia yang dipaksa aktif dari sisi server. Hasilnya, catatan audit tersanitasi di Neon PostgreSQL: bisa diaudit, tanpa menyimpan rahasia."

**On-screen text:** `DETERMINISTIC → AI → DETERMINISTIC` · `PRIVACY BOUNDARY` · `POLICY GATE` · `SANITIZED AUDIT / NEON POSTGRESQL`
**Morph out:** the ledger stack tips forward and its top row stretches into the closing frame's wordmark underline.

### ACT 4 — CLOSING · 01:45–02:00 · frames 2625–3000

| Time | Frame | Screen | Motion & camera |
| --- | --- | --- | --- |
| 01:45–01:52 | 2625–2800 | All prior elements — token chip, pipeline rail, boundary band, ledger — shrink and orbit once into a single emerald shield outline | One continuous pull-back + 12° orbit, 900 ms; elements fade at staggered 60 ms |
| 01:52–01:57 | 2800–2925 | Wordmark: **PYZEX GUARD**; line under it draws: *"Security should not slow teams down. It should help them ship with confidence."* | Underline draws left→right 400 ms; copy fades up |
| 01:57–02:00 | 2925–3000 | Credits micro-type, bottom-locked: `PIXZ.DEV` · `Tencent Cloud AI CAN DO IT Hackathon Indonesia 2026` · `Challenge B — The Office Agent`; tagline lockup: **PYZEX GUARD — Catch the leak before it ships.** | Hold 60 frames; 6-frame fade to obsidian at 02:00 |

**VO (01:45–02:00):**
"Keamanan seharusnya tidak memperlambat tim. Keamanan harus membantu mereka bekerja dengan lebih percaya diri. **Pyzex Guard — catch the leak before it ships.**"

**On-screen text (closing, bilingual):**
`Security should not slow teams down. It should help them ship with confidence.`
`Keamanan seharusnya tidak memperlambat tim. Keamanan harus membantu mereka bekerja dengan lebih percaya diri.`

---

## 2. Voice-over script (clean recording copy, Indonesian)

> Full VO ≈ 105 seconds of speech across four takes (one per act) — leaves
> breathing room under the 120-second picture lock.

**TAKE 1 (00:00–00:25):**
"Di alur kerja sehari-hari, satu baris di git diff bisa memuat kredensial cloud yang sah. Tidak perlu penyerang yang canggih — cukup satu commit yang terlewat. Pyzex Guard menangkap kebocoran itu sebelum terjadi: nilai rahasia disamarkan secara lokal, sebelum data menyentuh AI."

**TAKE 2 (00:25–01:15):**
"Ini dasbor aslinya. Saya muat konfigurasi demo — empat nilai sensitif terdeteksi secara lokal, dalam hitungan milidetik. Ini bagian terpenting: pratinjau privasi. Payload inilah yang benar-benar keluar ke AI — sudah tersamarkan, strukturnya utuh. Sekarang saya jalankan agent triage. Delapan tahap workflow berjalan dengan timing nyata per tahap. Hasilnya: temuan per kredensial, bukti tersamarkan, tingkat keyakinan, dan indeks risiko yang dihitung deterministik oleh server — bukan opini model. Dan usulan perbaikan: unified diff siap salin. Catatan rapat: patch ini hanya usulan — persetujuan manusia wajib, dan agent tidak pernah menerapkan perubahan."

**TAKE 3 (01:15–01:45):**
"Ini mengapa aman. Sebelum AI: PYSCAN dan redaksi lokal — deterministik, berjalan penuh di server aplikasi. Satu-satunya komponen probabilistik adalah inti AI di tengah: GLM-5.3-Flash lewat endpoint OpenAI-compatible bawaan sponsor, SumoPod — dikonfigurasi lewat environment variable, jadi provider bisa diganti tanpa mengubah logika. Setelah AI: gerbang kebijakan PYGUARD — validasi skema ketat, saringan kebocoran, dan konfirmasi manusia yang dipaksa aktif dari sisi server. Hasilnya, catatan audit tersanitasi di Neon PostgreSQL: bisa diaudit, tanpa menyimpan rahasia."

**TAKE 4 (01:45–02:00):**
"Keamanan seharusnya tidak memperlambat tim. Keamanan harus membantu mereka bekerja dengan lebih percaya diri. Pyzex Guard — catch the leak before it ships."

---

## 3. Sound design & music direction

- **Score:** one minimal electronic bed, 96–100 BPM, sub-heavy, no melodic
  lead until Act 4. Act-by-act: Act 1 sparse pulse + rising noise tension
  (crimson moment); Act 2 tightens — hats enter, side-chain pump aligned to
  stage-dot ignitions; Act 3 widest — pads, lowest energy; Act 4 single warm
  chord resolve + sub drop out on the final word.
- **Beat map:** scene boundaries land on musical downbeats at 00:25, 01:15,
  01:45; the token collapse (00:22) and the boundary slab (01:22) each get a
  dedicated percussive accent.
- **SFX palette (all synthesized/clinical, no "whoosh" clichés):** key click,
  relay click, single lock-clunk, data-tick (2 ms), low sub swell, one airy
  noise sweep for the camera arc in Act 3.
- **Mix:** VO −6 dBFS peak, music −18 dB under VO with 3 dB ducking, SFX −10 dB.
  Loudness target −16 LUFS (web).

---

## 4. Typography & palette lock

| Role | Face | Usage |
| --- | --- | --- |
| Data / code / labels | JetBrains Mono | diffs, tokens, stage labels, on-screen annotations |
| Narrative / titles | Inter (500/600) | titles ≤ 8 words, VO support lines |

Palette: obsidian `#0A0A0A` (canvas) · surface `#141414` (plates) · emerald
`#10B981` (safe/redacted/agent) · crimson `#EF4444` (exposure/boundary) ·
amber `#F59E0B` (policy/approval) · white `#F5F5F5` / gray `#8B8B8B` (type).
No gradients except a 4% vignette. No glow brighter than 12% alpha.

---

## 5. Product capture instructions (real UI, no fakery)

1. Run `npm start` locally; open `http://localhost:3000` at 1920×1080, browser zoom 100%, dark OS chrome hidden (`--start-fullscreen --incognito`).
2. Prepare in advance: Preset 1 loaded (or re-click it on camera — it's one click), cleared history panel is fine (its honest "PERSISTENCE INACTIVE" state is acceptable on screen; alternatively point `DATABASE_URL` at a throwaway Neon branch to show real rows).
3. Capture with a screen recorder at 3840×2160 → downscale to 1920×1080 for crisper UI type (OBS: 60 fps record, `shmf` not required; disable cursor highlight effects).
4. Record the exact Action list of Act 2 in order; keep total interaction ≤ 40 s so the edit can breathe.
5. Provider status must read truthfully: with `DEMO_MODE=true` and no API key, chips show `AI: DEMO/MOCK` and the result badge `MOCK FALLBACK` — **keep this visible**; the narration says so explicitly. When a live key is configured, re-record to show `LIVE AI ANALYSIS`.
6. Cursor: use a custom 8 px dot cursor for precision; hide OS cursor artifacts.
7. All credentials on screen remain the synthetic presets — no real secrets are ever typed or shown.

---

## 6. Motion rendering recommendations

- **Compositor:** code-driven (HTML/CSS/JS timeline render) or After Effects;
  either must honor: 25 fps constant, 1920×1080, additive-free palette,
  easing curves: `expoOut(0.16,1,0.3,1)` for entries, `spring(1,80,12)` for
  chip collapses, `expoInOut` for camera arcs.
- **Motion blur:** directional only on morphs > 300 px/frame; 3–5 px; never on
  typography at rest.
- **Type animation:** no per-letter bounce; per-letter opacity/track-in at
  8–12 ms stagger maximum.
- **Grain:** skip film grain — keep the render clinical; optional 1% noise on
  the obsidian background only, to prevent banding.
- **Export:** ProRes 422 HQ master + H.264 web derivative (CRF 18, AAC 320 kbps,
  −16 LUFS). Deliver 1920×1080 primary; optional 1080×1920 social recut using
  the same timeline with recentered safe areas.

---

## 7. Production checklist

- [ ] Record Act 2 screen capture (§5) — provider status visible & honest
- [ ] Record VO takes 1–4 (Indonesian) on one microphone in one room
- [ ] Build Act 1/3/4 motion scenes from the exact frame table (§1)
- [ ] Conform: scene boundaries on downbeats 00:25 / 01:15 / 01:45
- [ ] Mix audio to −16 LUFS; duck music under VO
- [ ] Verify: total duration = 120.00 s; last frame = 2999 (3000 frames total)
- [ ] Verify on-screen claims against the running app (no unbuilt features shown)

## 8. Honest-labeling notes for the edit

- The film must never present mock results as live AI analysis. When the
  capture shows `MOCK FALLBACK`, the VO/typography may say "demo", never "live".
- Latency numbers shown on screen must be the real measured values from the
  recorded session (`processing_ms`, per-stage `duration_ms`), not annotations
  typed by hand.
- If the provider goes live before the deadline, re-record Act 2 with
  `LIVE AI ANALYSIS` visible and update VO Take 2 line "dasbor aslinya" —
  nothing else changes.

## 9. Rendering status

This document ships as the **complete render-ready storyboard and production
instructions** (timeline, VO, SFX, capture plan, export specs). As of this
submission no MP4 has been rendered by the build environment; per the
project's honesty rules, no video file is claimed. The storyboard is scoped so
that any motion designer (or the author) can produce the final film in a
single session using only the running dashboard and the frame table above.
