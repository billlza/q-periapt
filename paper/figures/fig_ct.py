"""Fig: source->binary CT gate predicates with dependency-free planted-leak control."""
import numpy as np, matplotlib.pyplot as plt
import _ieee as I

rows = [  # (label, plotted value, display value, color, tag)
    ("ML-KEM-768 decaps\nmark secret (ŝ, z)", 0, "0", I.GREEN, "secret path clean"),
    ("synthetic control\nplanted secret branch", 1, ">0", I.VERM, "planted leak caught"),
    ("ML-KEM control\nsecret-indexed load", 1, ">0", I.GREY, "in-binary sanity caught"),
    ("ML-KEM attribution\nmark public key (ek)", 1, ">0", I.GREY, "public-data branch caught"),
]
fig, ax = plt.subplots(figsize=(I.COL, 2.35))
y = np.arange(len(rows))[::-1]
vals = [r[1] for r in rows]
cols = [r[3] for r in rows]
ax.barh(y, [max(v, 0.0) for v in vals], height=0.62, color=cols, edgecolor=I.BLACK, zorder=3)
ax.set_xlim(0, 1.38)
ax.set_xticks([0, 1])
ax.set_xticklabels(["0", ">0"])
ax.set_yticks(y); ax.set_yticklabels([r[0] for r in rows], fontsize=6.6)
ax.set_xlabel("registered Memcheck predicate (raw counts are ISA-specific evidence)")
ax.grid(axis="y", visible=False)
for yi, (_lbl, v, display, color, tag) in zip(y, rows):
    ax.annotate(f"{display}  —  {tag}", xy=(max(v, 0.0), yi), xytext=(4, 0),
                textcoords="offset points", va="center", ha="left", fontsize=6.0,
                color=(I.GREEN if v == 0 else (I.VERM if color == I.VERM else I.BLACK)))
ax.set_title("source→binary CT gate: zero plus non-vacuity controls", fontsize=8, pad=3)
I.save(fig, "fig_ct")
