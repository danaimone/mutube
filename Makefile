YOUTUBE_IPA := ./ipa/YouTube_4.54.01_decrypted.ipa
OUTPUT_IPA := ./mutube.ipa
# inject.js no longer fits the __TEXT header padding unminified, so embed a terser build of it.
INJECT_MIN := ./build/inject.min.js
TERSER := npx --yes terser@5.36.0
PATCHER_FLAGS :=

ifneq ($(PRINTF_LOGS),)
ifneq ($(PRINTF_LOGS),0)
PATCHER_FLAGS += --enable-printf-logs
endif
endif

ifneq ($(KEEP_SUPPORTED_DEVICES),)
ifneq ($(KEEP_SUPPORTED_DEVICES),0)
PATCHER_FLAGS += --keep-supported-devices
endif
endif

.PHONY: all
all: $(OUTPUT_IPA)

# Optional, gitignored: personal TizenTube settings seeded on first launch.
TT_DEFAULTS := $(wildcard tt-defaults.json)

$(INJECT_MIN): inject.js $(TT_DEFAULTS)
	mkdir -p $(dir $@)
	{ $(if $(TT_DEFAULTS),printf 'var MUTUBE_TT_DEFAULTS = '; cat $(TT_DEFAULTS); printf ';\n';) cat inject.js; } > $(dir $@)inject.src.js
	$(TERSER) $(dir $@)inject.src.js --compress --mangle -o $@

$(OUTPUT_IPA): $(YOUTUBE_IPA) patcher.py $(INJECT_MIN)
	uv run patcher.py --in $(YOUTUBE_IPA) --out $(OUTPUT_IPA) --inject $(INJECT_MIN) $(PATCHER_FLAGS)

.PHONY: clean
clean:
	rm -f $(OUTPUT_IPA) $(INJECT_MIN)
