# source top dir 
KLONE_SRC_DIR := $(shell pwd)

# makl vars
export MAKL_DIR := ${KLONE_SRC_DIR}/makl
MAKEFLAGS := -I ${MAKL_DIR}/mk

SUBDIR = build/libu webapp site src klone doc 

ifeq ($(wildcard Makefile.conf),)
help:
	@echo 
	@echo "  You must first run the configure script."
	@echo 
	@echo "  Run ./configure --help for the list of options"
	@echo 
endif

include $(MAKL_DIR)/mk/subdir.mk

# deps
webapp.all site.all src.all: build/libu.all
src.all: webapp.all site.all
contrib: src

