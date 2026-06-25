# Paper figures (Q-Periapt, TDSC)

Reproducible, IEEE-styled vector figures. `make` rebuilds every PDF.

| File | Figure | Shows |
|------|--------|-------|
| `fig_arch.pdf`    | Architecture (hero) | proof-to-byte cross-substrate: one proven core → 5 faces / 3 OS / 5 ISA → byte-identical `K` |
| `fig_binding.pdf` | Binding position    | the honest CDM ceiling — ContextBound & X-Wing both reach MAL-BIND-K-{CT,PK}; our edge = assumption-minimality, not a stronger notion; X-BIND-CT-* unachievable |
| `fig_ct.pdf`      | CT discriminator    | source→binary probe: ML-KEM secret = 0 flags, HQC = 193 (`vect_set_random_fixed_weight`); self-validating controls |
| `fig_netem.pdf`   | netem P99           | PQ/T overhead = ~fixed ~180µs CPU → negligible % at real RTT; combiner-neutral |
| `fig_kernel.pdf`  | §3 | reduction tower: MAL-BIND-K-{CT,PK,CTX} → CR(SHA3) via `encode_inj`; honest scope |
| `tbl_verif.pdf`   | §4 | the six orthogonal verification methods |
| `tbl_substrate.pdf`| §5 | cross-substrate coverage: (a) ISA targets, (b) faces × OS |
| `fig_wire.pdf`    | Wire budget         | PQ cost = one ML-KEM-768 keyshare each way (+2.27 KB), fits existing flights |

**Conventions (IEEE TDSC):** vector PDF, no raster text; serif (Times) ~7–8 pt; single-column
3.5 in (`_ieee.COL`); Okabe–Ito colorblind-safe palette + distinct markers/hatches for B&W;
units on every axis. Data figures: matplotlib (`_ieee.py` shared style). Diagrams: TikZ
(`build_tikz.sh` → `pdflatex` + `pdftoppm` PNG preview).

Rebuild: `make` (needs `python3`+`matplotlib`, `pdflatex`, `pdftoppm`). Data in `fig_netem.py`
is the measured `tc netem` run; regenerate raw numbers via `crates/q-periapt-rustls/examples/netem_bench.rs`.
