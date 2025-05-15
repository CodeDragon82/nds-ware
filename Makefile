PYTHON_PACKAGE=python-package
PYTHON_PARSERS=$(PYTHON_PACKAGE)/src/ndsware/parsers

JAVA_PACKAGE_NAME=ndsware.parsers
JAVA_SRC=java-package/src
JAVA_BUILD=java-package/build

GHIDRA_EXTENSION=ghidra-extension
GHIDRA_LIB=$(GHIDRA_EXTENSION)/lib

KAITAI_RUNTIME=$(GHIDRA_LIB)/kaitai-struct-runtime-0.10.jar

JAR_NAME=Ndsware.jar

all: python java ghidra

python:
	ksc -t python --outdir $(PYTHON_PARSERS) definitions/*
	pip wheel $(PYTHON_PACKAGE)/. --no-deps

java:
	ksc -t java --java-package $(JAVA_PACKAGE_NAME) --outdir $(JAVA_SRC) definitions/*
	javac -cp $(KAITAI_RUNTIME) -d $(JAVA_BUILD) $(shell find $(JAVA_SRC) -name "*.java")
	jar cf $(GHIDRA_LIB)/$(JAR_NAME) -C $(JAVA_BUILD) .

ghidra: java
	gradle -p $(GHIDRA_EXTENSION)
	cp $(GHIDRA_EXTENSION)/dist/* .