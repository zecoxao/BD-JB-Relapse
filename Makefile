JAR_NAME := Relapse.jar

MAKEFILE_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
BDJSDK_HOME  ?= $(MAKEFILE_DIR)/../../../../
JAVA8_HOME   ?= $(BDJSDK_HOME)/host/jdk8
JAVA11_HOME  ?= $(BDJSDK_HOME)/host/jdk11
JAVAC        := $(JAVA8_HOME)/bin/javac
JAR          := $(JAVA8_HOME)/bin/jar

export JAVA8_HOME
export JAVA11_HOME

# Build against the open bdj-sdk stubs (same classpath the ps5-* samples use), so
# the jar builds from public sources with no proprietary firmware jars. Override
# CLASSPATH on the command line to compile against a real bdjstack.jar + rt.jar.
CLASSPATH     ?= $(BDJSDK_HOME)/target/lib/enhanced-stubs.zip:$(BDJSDK_HOME)/target/lib/sony-stubs.jar
SOURCES       := $(wildcard src/org/bdj/api/*.java) $(wildcard src/org/bdj/*.java) $(wildcard src/org/bdj/external/*.java) 
JFLAGS        := -Xlint:-options -source 1.4 -target 1.4

all: $(JAR_NAME)

# Fetch the newest ps5-unified-autoloader release and regenerate
# PayloadPaths.java.  kexp/elfldr are pinned to loader-ABI-compatible builds;
# see README, "Payload versions".
payloads:
	bash scripts/update_payloads.sh

# Print the payload versions currently bundled in Relapse.jar.
payload-versions:
	bash scripts/update_payloads.sh --check

# Create JAR with manifest
$(JAR_NAME): $(SOURCES) manifest.txt
	$(JAVAC) $(JFLAGS) -cp $(CLASSPATH) $(SOURCES)
	$(JAR) cfm $@ manifest.txt -C src/ .

clean:
	rm -f src/org/bdj/api/*.class src/org/bdj/*.class src/org/bdj/external/*.class $(JAR_NAME)

.PHONY: all payloads payload-versions clean
