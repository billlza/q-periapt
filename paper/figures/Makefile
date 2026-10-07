# Q-Periapt paper figures.  `make` builds all PDFs (vector, IEEE-styled).
PY ?= python3
DATA := fig_netem fig_wire fig_ct
TIKZ := fig_arch fig_binding fig_kernel tbl_verif tbl_substrate
all: $(addsuffix .pdf,$(DATA) $(TIKZ))
$(addsuffix .pdf,$(DATA)): %.pdf: %.py _ieee.py ; $(PY) $<
$(addsuffix .pdf,$(TIKZ)): %.pdf: %.tex ; sh build_tikz.sh $*
clean: ; rm -f *.aux *.log *.png *-1.png *.synctex.gz
.PHONY: all clean
