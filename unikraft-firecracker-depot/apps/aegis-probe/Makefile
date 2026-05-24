# Wrapper around the Unikraft build system. `kraft build` populates
# workdir/ with the unikraft core + libs and then invokes this file.
# Mirrors the upstream app-helloworld layout.

UK_ROOT  ?= $(PWD)/workdir/unikraft
UK_LIBS  ?= $(PWD)/workdir/libs
UK_BUILD ?= $(PWD)/workdir/build
LIBS     :=

all:
	@$(MAKE) -C $(UK_ROOT) A=$(PWD) L=$(LIBS) O=$(UK_BUILD)

$(MAKECMDGOALS):
	@$(MAKE) -C $(UK_ROOT) A=$(PWD) L=$(LIBS) O=$(UK_BUILD) $(MAKECMDGOALS)
