"""Fig: socket TLS 1.3 time-to-session under real tc netem (rustls CryptoProvider).
Story: PQ/T overhead is a ~fixed ~180us CPU cost (no extra round-trip), so it vanishes
as RTT grows; ContextBound ~= CompatXWing (combiner-neutral)."""
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec
import _ieee as I

rtt = np.array([0, 20, 50])            # round-trip time, ms
xpos = np.arange(len(rtt))
p50 = {                                 # p50 time-to-session, us (real tc netem on lo)
    "X25519 (classical)":   np.array([360.3, 40968.8, 100969.3]),
    "ContextBound (PQ/T)":  np.array([564.2, 41148.9, 101110.1]),
    "CompatXWing (PQ/T)":   np.array([557.0, 41136.6, 101136.7]),
}
style = {
    "X25519 (classical)":  dict(c=I.GREY,   marker="o", ls="--"),
    "ContextBound (PQ/T)": dict(c=I.BLUE,   marker="s", ls="-"),
    "CompatXWing (PQ/T)":  dict(c=I.ORANGE, marker="^", ls="-"),
}

fig = plt.figure(figsize=(I.COL, 3.15))
gs = GridSpec(2, 1, height_ratios=[2.3, 1.0], hspace=0.16, figure=fig)
ax = fig.add_subplot(gs[0])
ax2 = fig.add_subplot(gs[1], sharex=ax)

# (a) absolute p50 time-to-session vs RTT (log-y) — three near-coincident curves.
for k, y in p50.items():
    ax.plot(xpos, y, label=k, markerfacecolor="white", markeredgewidth=1.1, **style[k])
ax.set_yscale("log")
ax.set_ylabel("time-to-session, p50 (µs)")
ax.set_ylim(230, 2.0e5)
ax.legend(loc="lower right", handlelength=1.9, borderaxespad=0.35, labelspacing=0.3)
ax.set_title("(a) latency is RTT-dominated — the three curves coincide", pad=3, fontsize=8)
ax.tick_params(labelbottom=False)

# (b) PQ/T overhead (ContextBound - classical): ~fixed CPU cost; % label shows it vanishing.
ov = p50["ContextBound (PQ/T)"] - p50["X25519 (classical)"]
pct = 100.0 * ov / p50["X25519 (classical)"]
ax2.bar(xpos, ov, width=0.5, color=I.BLUE, edgecolor=I.BLACK, alpha=0.85, zorder=3)
ax2.set_ylabel("PQ/T overhead\n(µs)", fontsize=7)
ax2.set_xlabel("emulated round-trip time (ms)")
ax2.set_xticks(xpos)
ax2.set_xticklabels([str(r) for r in rtt])
ax2.set_xlim(-0.55, 2.55)
ax2.set_ylim(0, max(ov) * 1.7)
ax2.grid(axis="x", visible=False)
for x, o, pc in zip(xpos, ov, pct):
    ax2.annotate(f"+{o:.0f} µs\n({pc:.2g}%)", xy=(x, o), xytext=(0, 2.5),
                 textcoords="offset points", ha="center", va="bottom", fontsize=6.3)
ax2.set_title("(b) overhead ≈ fixed CPU cost → negligible % at real RTT", pad=3, fontsize=8)

I.save(fig, "fig_netem")
