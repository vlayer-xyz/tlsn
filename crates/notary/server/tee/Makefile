# notary-server testing only
ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

SELF_EXE = ./notary-server

.PHONY: all
all: $(SELF_EXE) notary-server.manifest
ifeq ($(SGX),1)
all: notary-server.manifest.sgx notary-server.sig
endif

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

# Note that we're compiling in release mode regardless of the DEBUG setting passed
# to Make, as compiling in debug mode results in an order of magnitude's difference in
# performance that makes testing by running a benchmark with ab painful. The primary goal
# of the DEBUG setting is to control Gramine's loglevel.
-include $(SELF_EXE).d # See also: .cargo/config.toml
$(SELF_EXE): $(ROOT_DIR)../Cargo.toml
	cargo build --bin notary-server  --release --features tee_quote

notary-server.manifest: notary-server.manifest.template
	cp ../../../../target/release/notary-server . && \
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dself_exe=$(SELF_EXE) \
		$< $@

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# see the helloworld example for details on this workaround.
notary-server.manifest.sgx notary-server.sig: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: notary-server.manifest $(SELF_EXE)
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

ifeq ($(SGX),)
GRAMINE = gramine-direct
else
GRAMINE = gramine-sgx
endif

.PHONY: start-gramine-server
start-gramine-server: all
	$(GRAMINE) notary-server

.PHONY: clean
clean:
	$(RM) -rf *.token *.sig *.manifest.sgx *.manifest result-* OUTPUT

.PHONY: distclean
distclean: clean
	$(RM) -rf $(SELF_EXE) Cargo.lock

