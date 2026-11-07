.PHONY: all clean

BUILD := ../../target/continuity-paper
SOURCES := $(wildcard *.tex) references.bib

all: continuity.pdf

continuity.pdf: $(SOURCES)
	latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=$(BUILD) main.tex
	cp $(BUILD)/main.pdf $@

clean:
	latexmk -C -outdir=$(BUILD) main.tex
