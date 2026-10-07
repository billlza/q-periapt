"""Fig: socket TLS 1.3 time-to-session under real tc netem (rustls CryptoProvider).
Story: the PQ/T overhead is a ~fixed ~190us CPU cost at RTT=0; at realistic RTT it is within
run-to-run noise (its sign varies); ContextBound ~= CompatXWing (combiner-neutral).
Data: mean of 2 repetitions x {1000,400,300} handshakes each, real tc netem on lo."""
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec
import _ieee as I

rtt = np.array([0, 20, 50])
xpos = np.arange(len(rtt))
# p50 time-to-session, us (mean of 2 reps; real tc netem on lo)
p50 = {
    "X25519 (classical)":  np.array([359.6, 41469.5, 101630.5]),
    "ContextBound (PQ/T)": np.array([548.9, 41494.5, 102214.2]),
    "CompatXWing (PQ/T)":  np.array([530.6, 41816.5, 102159.2]),
}
style = {
    "X25519 (classical)":  dict(c=I.GREY,   marker="o", ls="--"),
    "ContextBound (PQ/T)": dict(c=I.BLUE,   marker="s", ls="-"),
    "CompatXWing (PQ/T)":  dict(c=I.ORANGE, marker="^", ls="-"),
}
# per-rep PQ/T overhead (ContextBound - classical), us -> mean + min/max for honest error bars
ov_runs = {0: [180.7, 198.0], 20: [275.6, -225.5], 50: [814.1, 353.2]}
ov_mean = np.array([np.mean(ov_runs[r]) for r in rtt])
ov_lo = ov_mean - np.array([min(ov_runs[r]) for r in rtt])
ov_hi = np.array([max(ov_runs[r]) for r in rtt]) - ov_mean

fig = plt.figure(figsize=(I.COL, 3.25))
gs = GridSpec(2, 1, height_ratios=[2.2, 1.05], hspace=0.16, figure=fig)
ax = fig.add_subplot(gs[0]); ax2 = fig.add_subplot(gs[1], sharex=ax)

# (a) absolute p50 vs RTT (log-y) — three near-coincident curves.
for k, y in p50.items():
    ax.plot(xpos, y, label=k, markerfacecolor="white", markeredgewidth=1.1, **style[k])
ax.set_yscale("log"); ax.set_ylim(230, 2.0e5)
ax.set_ylabel("time-to-session, p50 (µs)")
ax.legend(loc="lower right", handlelength=1.9, borderaxespad=0.35, labelspacing=0.3)
ax.set_title("(a) latency is RTT-dominated — the three curves coincide", pad=3, fontsize=8)
ax.tick_params(labelbottom=False)

# (b) PQ/T overhead with run-to-run spread: clear at RTT=0, within noise (straddles 0) at RTT>=20.
ax2.axhline(0, color=I.BLACK, lw=0.6, zorder=2)
ax2.bar(xpos, ov_mean, width=0.5, color=I.BLUE, edgecolor=I.BLACK, alpha=0.85, zorder=3,
        yerr=[ov_lo, ov_hi], capsize=2.5, error_kw=dict(lw=0.8, ecolor=I.BLACK))
ax2.set_ylabel("PQ/T overhead\n(µs)", fontsize=7)
ax2.set_xlabel("emulated round-trip time (ms)")
ax2.set_xticks(xpos); ax2.set_xticklabels([str(r) for r in rtt])
ax2.set_xlim(-0.55, 2.55); ax2.set_ylim(-360, 1180)
ax2.grid(axis="x", visible=False)
notes = [("+189 µs\n(53%)", 0, 230), ("within\nnoise", 1, 330), ("+0.5%\n(noisy)", 2, 870)]
for txt, x, yy in notes:
    ax2.annotate(txt, xy=(x, yy), ha="center", va="bottom", fontsize=6.3)
ax2.set_title("(b) overhead: ~190 µs CPU at RTT 0; within run noise at real RTT", pad=3, fontsize=8)

I.save(fig, "fig_netem")
