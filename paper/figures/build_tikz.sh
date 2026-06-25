#!/bin/sh
set -e
f="$1"
pdflatex -interaction=nonstopmode -halt-on-error "$f.tex" >/tmp/tex_$f.log 2>&1 || {
  echo "LATEX FAILED ($f):"; grep -iE '^!|error|undefined' /tmp/tex_$f.log | head -8; exit 1; }
pdftoppm -png -r 200 "$f.pdf" "$f" >/dev/null 2>&1
[ -f "$f-1.png" ] && mv "$f-1.png" "$f.png"
echo "ok: $f.pdf + $f.png"
