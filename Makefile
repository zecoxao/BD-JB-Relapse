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

# Optional: bundle an ELF that Relapse pushes to elfldr (:9021) once it is up,
# then closes the Disc Player.  Stored in the jar as /autoload.elf.
#   make AUTOLOAD_ELF=/path/to/payload.elf
AUTOLOAD_ELF  ?=
AUTOLOAD_DIR  := build/autoload

# Create JAR with manifest
$(JAR_NAME): $(SOURCES) manifest.txt $(AUTOLOAD_ELF) FORCE
	$(JAVAC) $(JFLAGS) -cp $(CLASSPATH) $(SOURCES)
	rm -rf $(AUTOLOAD_DIR) && mkdir -p $(AUTOLOAD_DIR)
ifneq ($(strip $(AUTOLOAD_ELF)),)
	cp "$(AUTOLOAD_ELF)" $(AUTOLOAD_DIR)/autoload.elf
endif
	$(JAR) cfm $@ manifest.txt -C src/ . -C $(AUTOLOAD_DIR) .

FORCE:
.PHONY: all clean FORCE

clean:
	rm -f src/org/bdj/api/*.class src/org/bdj/*.class src/org/bdj/external/*.class $(JAR_NAME)
	rm -rf $(AUTOLOAD_DIR)
