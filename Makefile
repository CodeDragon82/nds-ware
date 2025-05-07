PYTHON_PACKAGE=python-package
PYTHON_PARSERS=$(PYTHON_PACKAGE)/src/ndsware/parsers

JAVA_PACKAGE_NAME=ndsware.parsers
JAVA_SRC=java-package/src
JAVA_BUILD=java-package/build

KAITAI_RUNTIME=kaitai-struct-runtime-0.10.jar

JAR_NAME=Ndsware.jar

all: python

python:
	ksc -t python --outdir $(PYTHON_PARSERS) definitions/*
	pip install $(PYTHON_PACKAGE)/.

java:
	ksc -t java --java-package $(JAVA_PACKAGE_NAME) --outdir $(JAVA_SRC) definitions/*
	javac -cp $(KAITAI_RUNTIME) -d $(JAVA_BUILD) $(shell find $(JAVA_SRC) -name "*.java")
	jar cf $(JAR_NAME) -C $(JAVA_BUILD) .