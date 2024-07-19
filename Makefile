ARCH ?= x86_64

# Target
ifeq ($(ARCH), x86_64)
  TARGET := x86_64-unknown-none
else ifeq ($(ARCH), riscv64)
  TARGET := riscv64gc-unknown-none-elf
else ifeq ($(ARCH), aarch64)
  TARGET := aarch64-unknown-none
endif


define run_cmd
  @printf '$(WHITE_C)$(1)$(END_C) $(GRAY_C)$(2)$(END_C)\n'
  @$(1) $(2)
endef


doc_check_missing:
	$(call run_cmd,cargo doc,--no-deps --all-features --workspace)


clippy:
ifeq ($(origin ARCH), command line)
	cargo clippy --all-features --workspace --target $(TARGET)
else
	cargo clippy --all-features --workspace 
endif
