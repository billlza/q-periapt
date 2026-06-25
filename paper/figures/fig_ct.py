"""Fig: source->binary constant-time gap probe is a DISCRIMINATOR. Same Memcheck harness:
clean ML-KEM secret = 0 flags, leaky HQC = 193; controls validate the harness."""
import numpy as np, matplotlib.pyplot as plt
import _ieee as I

rows = [  # (label, flags, color, tag)
    ("ML-KEM-768 decaps\nmark secret (ŝ, z)",        0,    I.GREEN, "no source→binary gap"),
    ("HQC decaps\nmark secret prefix",                193,  I.VERM,  "leak: vect_set_random_fixed_weight"),
    ("[neg. control] planted\nsecret-indexed load",   1,    I.GREY,  "harness catches a leak"),
    ("[pos. control] ML-KEM\nmark public key (ek)",   5696, I.GREY,  "Memcheck flags real branches"),
]
fig, ax = plt.subplots(figsize=(I.COL, 2.35))
y = np.arange(len(rows))[::-1]
vals = [r[1] for r in rows]
cols = [r[2] for r in rows]
ax.barh(y, [max(v, 0.0) for v in vals], height=0.62, color=cols, edgecolor=I.BLACK, zorder=3)
ax.set_xscale("symlog", linthresh=1.0)
ax.set_xlim(0, 2.0e4)
ax.set_xticks([0, 1, 10, 100, 1000, 10000])
ax.set_xticklabels(["0", "1", "10", "100", "1k", "10k"])
ax.set_yticks(y); ax.set_yticklabels([r[0] for r in rows], fontsize=6.6)
ax.set_xlabel("Memcheck secret-dependent reports (symlog)")
ax.grid(axis="y", visible=False)
for yi, (lbl, v, c, tag) in zip(y, rows):
    ax.annotate(f"{v}  —  {tag}", xy=(max(v, 0.0), yi), xytext=(4, 0),
                textcoords="offset points", va="center", ha="left", fontsize=6.0,
                color=(I.GREEN if v == 0 else (I.VERM if c == I.VERM else I.BLACK)))
ax.set_title("source→binary CT probe discriminates clean vs leaky", fontsize=8, pad=3)
I.save(fig, "fig_ct")
