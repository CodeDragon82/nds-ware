PYTHON_PACKAGE=python-package
PYTHON_PARSERS=$(PYTHON_PACKAGE)/src/ndsware/parsers

all: python

python:
	ksc -t python --outdir $(PYTHON_PARSERS) definitions/*
	pip install $(PYTHON_PACKAGE)/.
