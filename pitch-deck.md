# Pyzex Guard — Pitch Deck

*Five slides. English-first titles, Indonesian supporting copy, Indonesian speaker notes.*
*Visual system: PIXZ.DEV Security Operations — obsidian `#0A0A0A`, surface `#141414`, emerald `#10B981`, crimson `#EF4444`, neutral white `#F5F5F5`, muted gray `#8B8B8B`. Typeface: JetBrains Mono for labels/data, Inter for narrative. One restrained accent per slide; no neon, no glassmorphism, no stock dashboard chrome.*

---

## SLIDE 1 — THE PROBLEM

### Title: **The Silent Office Breach**

**Narrative (on slide):**

- Satu kredensial yang bocor secara tidak sengaja cukup untuk membuka akses ke infrastruktur cloud perusahaan.
- Alur kebocoran paling umum terjadi di pekerjaan kantor sehari-hari:

```text
Developer ─▶ Git Diff ─▶ Exposed Credential ─▶ Potential Security Incident
```

- Review manual lambat, mahal, dan mudah terlewat — sementara deadline tetap berjalan.

**Target users:** development teams · DevOps teams · SMEs · remote engineering teams.

**Speaker notes (ID):**
"Bayangkan pekerjaan kantor yang paling biasa: seorang developer menyelesaikan perbaikan kecil, membuka diff, lalu menekan commit. Tanpa dia sadari, di dalam diff itu ada satu baris berisi kredensial cloud produksi. Tidak ada niat jahat di sini — hanya tekanan deadline dan review manual yang terlewat. Masalah yang kami anggap bukan 'serangan canggih', melainkan kecelakaan operasional yang diam-diam, terjadi berulang, dan mahal konsekuensinya. Kami tidak membawa statistik insiden yang tidak bisa kami buktikan — fokus kami pada pola kerja yang jelas Anda kenal: Developer → Git Diff → Kredensial Terekspos → Potensi Insiden."

**Visual direction:**
- *Composition:* full-bleed obsidian canvas; one oversized diff line rendered center-frame, monospace, with a single credential value glowing crimson — the only red pixel on the slide.
- *Diagram:* the four-step flow as connected mono chips along the bottom third, connected by thin lines.
- *Typography:* "The Silent Office Breach" in Inter 64–72 pt; supporting copy ≤ 2 lines, muted gray.
- *Focal element:* the exposed credential value — everything else is dimmed 40%.
- *Transition (in):* the diff line types itself once, then the credential value "leaks" — a thin crimson underline spreads horizontally to the flow diagram.

---

## SLIDE 2 — THE SOLUTION

### Title: **Meet Pyzex Guard**

**Narrative (on slide):**

- Agen keamanan operasional (SecOps Office Agent) yang *privacy-first*.
- Lima kemampuan inti dalam satu alur kerja:

```text
① Local secret detection   ② Context-aware AI triage   ③ Risk analysis
④ Remediation drafting     ⑤ Human approval
```

- Data sensitif **disamarkan secara lokal sebelum** menyentuh AI. AI menganalisis struktur dan tipe — bukan nilai rahasianya.
- Sesuai **Challenge B — Automating Better**: mengotomatiskan rutinitas review keamanan yang repetitif, tanpa mengorbankan akuntabilitas manusia.

**Speaker notes (ID):**
"Pyzex Guard adalah 'petugas office' khusus keamanan: dia bekerja otomatis di alur kerja yang repetitif — memindai materi yang akan dikirim, menyamarkan bagian sensitif secara lokal, memanggil AI untuk triase kontekstual, menyusun usulan perbaikan, lalu menyerahkan keputusan akhir ke manusia. Kata kuncinya: otomatisasi tugasnya, otentik kebijakannya. Ini jawaban kami untuk Challenge B — Automating Better: bukan automating everything. AI kami tidak pernah menekan tombol deploy."

**Visual direction:**
- *Composition:* left 60% — the five capability chips stacked as a vertical workflow; right 40% — a compact before/after code panel showing raw lines morphing into `[REDACTED:*]` tokens.
- *Diagram:* the redaction arrow between the two panels is the widest visual element — labeled "PRIVACY BOUNDARY / BATAS PRIVASI".
- *Typography:* Inter for capability names, JetBrains Mono for the code panel; emerald used only on the redaction tokens.
- *Focal element:* the privacy boundary arrow.
- *Transition:* raw values collapse into tokens one by one (stagger 80 ms), then the boundary arrow draws itself.

---

## SLIDE 3 — ARCHITECTURE & SPONSOR INTEGRATION

### Title: **Built for Safe Agentic Workflows**

**Narrative (on slide):**

- **Deterministik:** validasi request · deteksi & redaksi lokal · validasi output · policy gate · risk index · audit store.
- **AI-assisted:** triase keamanan kontekstual via GLM-5.3-Flash (SumoPod, endpoint OpenAI-compatible).
- **PYSCAN** (deteksi & sanitasi lokal) dan **PYGUARD** (validasi kebijakan & forced human approval) adalah dua gerbang deterministik yang mengapit panggilan AI.
- Audit tersanitasi tersimpan di **Neon PostgreSQL** — metadata dan bukti tersamarkan, tanpa nilai mentah.
- Model **tidak pernah** menerima nilai rahasia pada konfigurasi default (`REDACT`).

**Speaker notes (ID):**
"Ini arsitektur yang jujur: hanya satu bagian di diagram ini yang probabilistik — panggilan AI di tengah. Segala sesuatu sebelum dan sesudahnya adalah kode deterministik yang bisa kami uji. PYSCAN mendeteksi dan menyamarkan secara lokal; payload yang keluar hanya berisi placeholder bertipe seperti REDACTED:CLOUD_SECRET_ID. Panggilan inference berjalan ke endpoint OpenAI-compatible bawaan sponsor — SumoPod — dengan model GLM-5.3-Flash, dikonfigurasi lewat environment variable sehingga provider bisa diganti tanpa menyentuh logika aplikasi. Semua keluaran model harus lolos skema JSON ketat dan gerbang kebijakan PYGUARD: konfirmasi manusia dipaksa aktif di sisi server. Jejak audit tersanitasi masuk ke Neon PostgreSQL. Deterministik di tepi, AI di inti — dengan pagar di kedua sisi."

**Visual direction:**
- *Composition:* horizontal pipeline spanning the slide: `PYSCAN → LOCAL REDACTION → [AI CORE: GLM-5.3-Flash] → PYGUARD → NEON`, with the AI core rendered as a slightly raised plate.
- *Diagram:* a vertical crimson "privacy boundary" band drawn between LOCAL REDACTION and the AI core; a second amber "policy gate" band between the AI core and PYGUARD.
- *Labels:* sponsor tags in mono chips — `SumoPod · OpenAI-compatible`, `GLM-5.3-Flash`, `Neon Postgres`.
- *Typography:* stage names Inter 600; data-flow annotations mono 11 px.
- *Focal element:* the privacy boundary band — labeled, not decorative.
- *Transition:* the pipeline assembles left-to-right; when the AI plate lands, the boundary bands flash once and settle.

---

## SLIDE 4 — LIVE PRODUCT CAPABILITIES

### Title: **From Exposed Secret to Actionable Fix**

**Narrative (on slide):**

Demo langsung, tujuh langkah, satu permintaan API:

```text
① Paste vulnerable diff      ② Local detection          ③ Privacy preview
④ Agent triage               ⑤ Findings + risk index     ⑥ Remediation draft
⑦ Sanitized audit record
```

- Setiap langkah terlihat di dasbor — termasuk **payload tersanitasi** yang benar-benar dikirim ke AI.
- Risiko dihitung deterministik di server (bukan opini model); indeks risiko + bobot per temuan.
- Latensi yang ditampilkan adalah **hasil pengukuran nyata** dari sesi demo — tidak ada klaim "di bawah 2 detik" tanpa benchmark.
- Mode demo ditampilkan jujur: `LIVE AI ANALYSIS` vs `MOCK FALLBACK` vs `PROVIDER UNAVAILABLE`.

**Speaker notes (ID):**
"Sekarang produknya, bukan slide-nya. Saya tempel diff yang mengandung kredensial palsu, sistem mendeteksi empat nilai sensitif secara lokal — perhatikan panel Privacy Preview: inilah persisnya payload yang keluar ke AI, sudah tersamarkan. Saya tekan Trigger Agent Triage; strip workflow atas menunjukkan delapan tahap berjalan dengan timing nyata per tahap. Hasilnya: temuan per kredensial dengan bukti tersamarkan, tingkat keyakinan, saran remediasi, dan indeks risiko yang dihitung server — angka yang bisa direproduksi, bukan perasaan model. Terakhir, usulan patch siap salin, dan catatan audit tersanitasi. Semua status ditampilkan jujur — kalau ini mode demo, dasbor bilang mode demo."

**Visual direction:**
- *Composition:* a single wide dashboard screenshot (the real product) as the slide background at 70% scale, with three numbered callout rings: Privacy Preview, Findings + Risk gauge, Copy Patch.
- *Diagram:* the seven steps as a thin progress rail along the top.
- *Typography:* callout labels mono 10 px, uppercase, tracking wide.
- *Focal element:* the risk gauge — the only circular element on the slide.
- *Transition:* callout rings pulse in sequence 1→3; no other motion. Screen-recording beats replace transitions.

---

## SLIDE 5 — BUSINESS IMPACT & ROADMAP

### Title: **Shift Security Left. Reduce Operational Friction.**

**Narrative (on slide):**

Nilai operasional (target & hipotesis produk — bukan hasil pilot):

- **Deteksi lebih awal** — kebocoran tertangkap sebelum commit/push, bukan setelah insiden.
- **Triase lebih cepat** — ringkasan, dampak, dan usulan perbaikan tersedia dalam satu alur kerja.
- **Beban review manual turun** — reviewer hanya menangani temuan bernilai, dengan bukti tersamarkan yang aman dibagikan.
- **Auditabilitas** — jejak tersanitasi di Neon PostgreSQL, siap untuk kepatuhan internal.
- **Adopsi AI yang sadar privasi** — pola kerja yang bisa dipertanggungjawabkan oleh tim keamanan.

Roadmap:

```text
MVP (hari ini)  ─▶  GitHub/GitLab workflow integration  ─▶  Team policies & role-based approvals  ─▶  Enterprise audit integrations
Snippet & diff     PR scanning via CI hooks                Approval routing per tim               SIEM / GRC export
```

**Speaker notes (ID):**
"Semua angka di slide ini saya sebut apa adanya: target dan hipotesis, bukan hasil pilot — kami tidak menjual statistik yang belum kami buktikan. Nilai yang sudah nyata hari ini: alur kerja yang berjalan, batas privasi yang bisa diuji, dan jejak audit yang jujur. Ke depan: integrasi workflow GitHub/GitLab agar pemindaian terjadi di pull request; kebijakan tim dan approval berbasis peran; lalu ekspor audit untuk kebutuhan enterprise. Visi kami sederhana: keamanan seharusnya tidak memperlambat tim — keamanan harus membantu mereka bekerja dengan lebih percaya diri. Pyzex Guard — catch the leak before it ships."

**Visual direction:**
- *Composition:* top two-thirds — five impact statements as a clean list with thin emerald tick rails; bottom third — the roadmap as a four-node horizontal timeline with the current stage filled solid.
- *Typography:* headline Inter 600 44 pt; impact statements 18 pt; roadmap labels mono 10 px.
- *Focal element:* the roadmap's "MVP — hari ini" node, solid emerald; future nodes outlined.
- *Transition:* roadmap nodes draw in sequence, left to right, ending on the solid MVP node.
- *Closing frame:* small centered wordmark `PYZEX GUARD — Catch the leak before it ships.` with credits line `PIXZ.DEV · Tencent Cloud AI CAN DO IT Hackathon Indonesia 2026 · Challenge B — The Office Agent`.

---

*All preset/demo credentials used in this deck's screenshots are synthetic and non-functional. Latency figures are to be captured live from the running application during recording — never estimated.*
