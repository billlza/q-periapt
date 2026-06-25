"""Fig: TLS 1.3 handshake wire budget — classical vs PQ/T hybrid. The PQ cost is one
ML-KEM-768 keyshare each way (+2.27 KB), which fits inside the existing flights (no extra RT)."""
import numpy as np, matplotlib.pyplot as plt
import _ieee as I

shared = 968                  # classical total (X25519 + cert + ML-DSA-less TLS framing), bytes
ek, ct = 1184, 1088           # ML-KEM-768 encapsulation key (c->s) + ciphertext (s->c)
fig, ax = plt.subplots(figsize=(I.COL, 2.15))
x = [0, 1]
ax.bar(x[0], shared, width=0.55, color=I.GREY, edgecolor=I.BLACK, label="classical handshake (X25519, cert, TLS)")
ax.bar(x[1], shared, width=0.55, color=I.GREY, edgecolor=I.BLACK)
ax.bar(x[1], ek, bottom=shared, width=0.55, color=I.BLUE, edgecolor=I.BLACK, hatch="///", label="ML-KEM-768 encap key (client→server)")
ax.bar(x[1], ct, bottom=shared + ek, width=0.55, color=I.SKY, edgecolor=I.BLACK, hatch="\\\\\\", label="ML-KEM-768 ciphertext (server→client)")
for xi, tot in [(0, shared), (1, shared + ek + ct)]:
    ax.annotate(f"{tot:,} B" if tot < 1000 else f"{tot/1024:.1f} KB", xy=(xi, tot),
                xytext=(0, 3), textcoords="offset points", ha="center", fontsize=7.5, fontweight="bold")
ax.annotate("+1184 B", xy=(1, shared + ek / 2), ha="center", va="center", fontsize=6.4, color="white")
ax.annotate("+1088 B", xy=(1, shared + ek + ct / 2), ha="center", va="center", fontsize=6.4, color=I.BLACK)
ax.set_xticks(x); ax.set_xticklabels(["X25519\n(classical)", "Q-Periapt\n(PQ/T hybrid)"])
ax.set_ylabel("handshake bytes on the wire")
ax.set_ylim(0, 3700); ax.set_xlim(-0.6, 1.6)
ax.grid(axis="x", visible=False)
ax.legend(loc="upper left", fontsize=6.2, handlelength=1.3, borderaxespad=0.3, labelspacing=0.3)
ax.set_title("PQ/T cost = one ML-KEM-768 keyshare each way (+2.27 KB)", fontsize=8, pad=3)
I.save(fig, "fig_wire")
