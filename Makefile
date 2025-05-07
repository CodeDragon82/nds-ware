PYTHON_PACKAGE=python-package
PYTHON_PARSERS=$(PYTHON_PACKAGE)/src/ndsware/parsers

JAVA_SRC_ROOT=java-package/src/com/ndsware
JAVA_BUILD=java-package/build
JAVA_PARSERS=$(JAVA_SRC_ROOT)/parsers

KAITAI_RUNTIME=kaitai-struct-runtime-0.10.jar

all: python

python:
	ksc -t python --outdir $(PYTHON_PARSERS) definitions/*
	pip install $(PYTHON_PACKAGE)/.

java:
	ksc -t java --outdir $(JAVA_PARSERS) definitions/*
	javac -cp $(KAITAI_RUNTIME) -d $(JAVA_BUILD) $(JAVA_PARSERS)/*.java
	jar cf Ndsware.jar -C $(JAVA_BUILD) .