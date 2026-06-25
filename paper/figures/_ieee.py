"""Shared IEEE-style matplotlib config for the Q-Periapt paper figures.

IEEE TDSC conventions: vector PDF, serif (Times) ~7-8pt, single-column 3.5in,
colorblind-safe + B&W-distinguishable (Okabe-Ito palette + distinct markers/hatches).
"""
import matplotlib as mpl

mpl.use("pdf")
mpl.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "STIXGeneral", "DejaVu Serif"],
    "mathtext.fontset": "stix",
    "font.size": 8,
    "axes.labelsize": 8,
    "axes.titlesize": 8.5,
    "legend.fontsize": 7,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7,
    "axes.linewidth": 0.7,
    "lines.linewidth": 1.3,
    "lines.markersize": 4.5,
    "patch.linewidth": 0.7,
    "savefig.dpi": 600,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.015,
    "axes.grid": True,
    "grid.linewidth": 0.4,
    "grid.alpha": 0.35,
    "grid.color": "#999999",
    "legend.frameon": False,
    "axes.axisbelow": True,
})

# Okabe-Ito colorblind-safe palette.
BLUE   = "#0072B2"
ORANGE = "#E69F00"
GREEN  = "#009E73"
VERM   = "#D55E00"
PURPLE = "#CC79A7"
SKY    = "#56B4E9"
BLACK  = "#222222"
GREY   = "#888888"

COL = 3.5      # single-column width, inches
COL2 = 7.16    # double-column width, inches

def save(fig, name):
    out = f"{name}.pdf"
    fig.savefig(out)
    # also a PNG for quick visual verification
    fig.savefig(f"{name}.png", dpi=200)
    print("wrote", out)
