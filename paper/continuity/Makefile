.PHONY: all check source clean

BUILD := build
PYTHON ?= python3
TEX_SOURCES := $(filter-out joc-submission.tex,$(wildcard *.tex))
SOURCES := $(TEX_SOURCES) references.bib sn-jnl.cls joc-basic.bst

all: continuity.pdf

joc-submission.tex: $(TEX_SOURCES) flatten_manuscript.py
	$(PYTHON) "$(CURDIR)/flatten_manuscript.py"

figures/confirmation-cut.pdf: figures/confirmation-cut.tex figures/confirmation-cut.tikz
	mkdir -p $(BUILD)/figures
	cd figures && latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=../$(BUILD)/figures confirmation-cut.tex
	cp $(BUILD)/figures/confirmation-cut.pdf $@

continuity.pdf: joc-submission.tex $(SOURCES) figures/confirmation-cut.pdf
	latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=$(BUILD) joc-submission.tex
	cp $(BUILD)/joc-submission.pdf $@

check: continuity.pdf
	$(PYTHON) "$(CURDIR)/artifacts/chain-prefix/check_prefix.py"
	$(PYTHON) "$(CURDIR)/artifacts/native-online-chain/check_native_chain.py"
	$(PYTHON) "$(CURDIR)/artifacts/matched-comparison/analyze_matched.py" --check
	$(PYTHON) "$(CURDIR)/artifacts/matched-comparison/check_input_controls.py"
	$(PYTHON) "$(CURDIR)/artifacts/matched-comparison/test_audit_input_boundaries.py"
	$(PYTHON) "$(CURDIR)/artifacts/retry-readiness/analyze_retry.py" --check
	$(PYTHON) "$(CURDIR)/check_build.py"

source: check
	$(PYTHON) "$(CURDIR)/export_submission.py" --output "$(CURDIR)/$(BUILD)/joc-source.zip"

clean:
	latexmk -C -outdir=$(BUILD) joc-submission.tex
	cd figures && latexmk -C -outdir=../$(BUILD)/figures confirmation-cut.tex
