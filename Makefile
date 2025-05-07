PYTHON_PACKAGE=python-package
PYTHON_PARSERS=$(PYTHON_PACKAGE)/src/ndsware/parsers

JAVA_PACKAGE=java-package
JAVA_SRC_ROOT=$(JAVA_PACKAGE)/src/com/ndsware
JAVA_BUILD=$(JAVA_PACKAGE)/build
JAVA_PARSERS=$(JAVA_SRC_ROOT)/parsers

KAITAI_RUNTIME=kaitai-struct-runtime-0.10.jar

JAR_NAME=Ndsware.jar

all: python

python:
	ksc -t python --outdir $(PYTHON_PARSERS) definitions/*
	pip install $(PYTHON_PACKAGE)/.

java:
	ksc -t java --outdir $(JAVA_PARSERS) definitions/*
	javac -cp $(KAITAI_RUNTIME) -d $(JAVA_BUILD) $(JAVA_PARSERS)/*.java
	jar cf $(JAR_NAME) -C $(JAVA_BUILD) .