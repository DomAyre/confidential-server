DEPS_DIR := tools/cose-deps
TCOSE_DIR := $(DEPS_DIR)/t_cose
QCBOR_DIR := $(DEPS_DIR)/qcbor
CC := gcc
CFLAGS := -Wall -Wextra -O2 -Isrc/core \
          -I$(TCOSE_DIR)/inc -I$(TCOSE_DIR)/src \
          -I$(QCBOR_DIR)/inc \
          -DT_COSE_USE_OPENSSL_CRYPTO=1
LDFLAGS := -lcrypto -lm

ifeq ($(COVERAGE),1)
CFLAGS += --coverage -O0
LDFLAGS += --coverage
endif

ifdef ASAN
CFLAGS  += -fsanitize=address -fno-omit-frame-pointer -g
LDFLAGS += -fsanitize=address
export ASAN_OPTIONS = detect_leaks=1:print_summary=1
endif

BUILD_DIR := build
SRC_DIR := src/core
TEST_DIR := test

CORE_SRCS := $(wildcard $(SRC_DIR)/*.c)
BINS := $(notdir $(CORE_SRCS:.c=))
BIN_PATHS := $(addprefix $(BUILD_DIR)/,$(BINS))
COSE_SRCS := \
    $(TCOSE_DIR)/src/t_cose_sign1_verify.c \
    $(TCOSE_DIR)/src/t_cose_util.c \
    $(TCOSE_DIR)/src/t_cose_parameters.c \
    $(TCOSE_DIR)/src/t_cose_short_circuit.c \
    $(TCOSE_DIR)/crypto_adapters/t_cose_openssl_crypto.c \
    $(QCBOR_DIR)/src/qcbor_decode.c \
    $(QCBOR_DIR)/src/qcbor_encode.c \
    $(QCBOR_DIR)/src/UsefulBuf.c \
    $(QCBOR_DIR)/src/ieee754.c
LIB_SRCS := $(wildcard $(SRC_DIR)/lib/*.c) $(wildcard $(SRC_DIR)/lib/*.S) $(COSE_SRCS)
TEST_BINARIES := \
    $(BUILD_DIR)/test_base64_unit \
    $(BUILD_DIR)/test_hex_unit \
    $(BUILD_DIR)/test_files_unit \
    $(BUILD_DIR)/test_sha256_unit \
    $(BUILD_DIR)/test_json_unit \
    $(BUILD_DIR)/test_cert_chain_unit \
    $(BUILD_DIR)/test_host_amd_certs_unit \
    $(BUILD_DIR)/test_snp_report_unit \
    $(BUILD_DIR)/test_uvm_endorsements_unit \

DEPS := deps
.PHONY: all clean test test_unit test_python lint $(BINS) $(DEPS) asan

all: $(DEPS) $(BIN_PATHS)

compile-commands:
	@echo "Generating compile_commands.json with bear..."
	@bear -- make clean all

docker:
	@docker compose build

python:
	@(cd src/bindings/python/ && python3 -m pip install -e .)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%: $(SRC_DIR)/%.c $(LIB_SRCS) | $(BUILD_DIR) $(DEPS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Link QCBOR spiffy decode if present (for newer QCBOR)
ifeq (,$(wildcard $(QCBOR_DIR)/src/qcbor_spiffy_decode.c))
# No spiffy decode source file, do nothing
else
LIB_SRCS += $(QCBOR_DIR)/src/qcbor_spiffy_decode.c
endif

# Phony targets for individual programs
$(BINS): %: $(BUILD_DIR)/%


lint_deps: deps
	@echo "Installing lint dependencies..."
	@sudo apt-get update && sudo apt-get install -y \
		clang-tidy

coverage_deps:
	@echo "Installing test dependencies..."
	@sudo apt-get update && sudo apt-get install -y \
		lcov

test: test_unit test_system test_python test_docker
	@echo "All tests passed"

test_unit: $(TEST_BINARIES)
	@$(BUILD_DIR)/test_base64_unit
	@$(BUILD_DIR)/test_hex_unit
	@$(BUILD_DIR)/test_files_unit
	@$(BUILD_DIR)/test_sha256_unit
	@$(BUILD_DIR)/test_json_unit
	@$(BUILD_DIR)/test_cert_chain_unit
	@$(BUILD_DIR)/test_host_amd_certs_unit
	@$(BUILD_DIR)/test_snp_report_unit
	@$(BUILD_DIR)/test_uvm_endorsements_unit

test_system: all
	./build/get_attestation_ccf "example-report-data" \
		| xargs -0 ./build/verify_attestation_ccf \
			--report-data "example-report-data" \
			--security-policy-b64 "$$(cat examples/security_policies/allow_all.rego | base64 -w 0)"

test_docker: all docker
	docker compose up --build --abort-on-container-failure

test_python: all python
	@echo "Running Python pytest suite..."
	pip install -r test/python/requirements.txt
	pytest -q test/python

lint: lint_deps
	@echo "Running clang-tidy over C sources..."
	@clang-tidy -p compile_commands.json $(SRC_DIR)/lib/*.c -- $(CFLAGS)

coverage: coverage_deps
	-@$(MAKE) clean
	-@$(MAKE) COVERAGE=1 test_unit
	@echo "Capturing coverage data..."
	@lcov --capture --directory $(BUILD_DIR) --output-file $(BUILD_DIR)/coverage.info
	@echo "Generating HTML report..."
	@genhtml $(BUILD_DIR)/coverage.info --output-directory $(BUILD_DIR)/coverage_html
	@echo "Coverage report generated in $(BUILD_DIR)/coverage_html/index.html"

asan:
	$(MAKE) ASAN=1 test_system

test_aci:
	c-aci-testing target run . \
		--policy-type "allow_all" \
		--deployment-name "test-aci"

deps:
	@mkdir -p $(DEPS_DIR)
	@echo "Fetching t_cose into $(TCOSE_DIR)..."
	@if [ ! -d "$(TCOSE_DIR)" ]; then git clone --recursive https://github.com/laurencelundblade/t_cose.git $(TCOSE_DIR); fi
	@echo "Fetching QCBOR into $(QCBOR_DIR)..."
	@if [ ! -d "$(QCBOR_DIR)" ]; then git clone https://github.com/laurencelundblade/qcbor.git $(QCBOR_DIR); fi

$(BUILD_DIR)/test_base64_unit: $(TEST_DIR)/test_base64_unit.c $(SRC_DIR)/lib/base64.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ \
		$(TEST_DIR)/test_base64_unit.c \
		$(SRC_DIR)/lib/base64.c \
		$(LDFLAGS)

# Unit tests for other core libraries
$(BUILD_DIR)/test_hex_unit: $(TEST_DIR)/test_hex_unit.c $(SRC_DIR)/lib/hex.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ \
		$(TEST_DIR)/test_hex_unit.c \
		$(SRC_DIR)/lib/hex.c \
		$(LDFLAGS)

$(BUILD_DIR)/test_files_unit: $(TEST_DIR)/test_files_unit.c $(SRC_DIR)/lib/files.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ \
		$(TEST_DIR)/test_files_unit.c \
		$(SRC_DIR)/lib/files.c \
		$(LDFLAGS)

$(BUILD_DIR)/test_sha256_unit: $(TEST_DIR)/test_sha256_unit.c $(SRC_DIR)/lib/sha256.c $(SRC_DIR)/lib/hex.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ \
		$(TEST_DIR)/test_sha256_unit.c \
		$(SRC_DIR)/lib/sha256.c \
		$(SRC_DIR)/lib/hex.c \
		$(LDFLAGS)

$(BUILD_DIR)/test_json_unit: $(TEST_DIR)/test_json_unit.c $(SRC_DIR)/lib/json.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ \
		$(TEST_DIR)/test_json_unit.c \
		$(SRC_DIR)/lib/json.c \
		$(LDFLAGS)

$(BUILD_DIR)/test_cert_chain_unit: \
    $(TEST_DIR)/test_cert_chain_unit.c \
    $(SRC_DIR)/lib/cert_chain.c \
    $(SRC_DIR)/lib/json.c \
    $(SRC_DIR)/lib/base64.c \
    $(SRC_DIR)/lib/host_amd_certs.c \
    $(SRC_DIR)/lib/files.c \
    $(SRC_DIR)/lib/snp_report.c \
    $(SRC_DIR)/lib/sha256.c \
    $(SRC_DIR)/lib/embedded_examples.S | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ \
		$(TEST_DIR)/test_cert_chain_unit.c \
		$(SRC_DIR)/lib/cert_chain.c \
		$(SRC_DIR)/lib/json.c \
		$(SRC_DIR)/lib/base64.c \
		$(SRC_DIR)/lib/host_amd_certs.c \
		$(SRC_DIR)/lib/files.c \
		$(SRC_DIR)/lib/snp_report.c \
		$(SRC_DIR)/lib/sha256.c \
		$(SRC_DIR)/lib/embedded_examples.S \
		$(LDFLAGS)

# Unit test for host_amd_certs
$(BUILD_DIR)/test_host_amd_certs_unit: $(TEST_DIR)/test_host_amd_certs_unit.c $(SRC_DIR)/lib/host_amd_certs.c $(SRC_DIR)/lib/json.c $(SRC_DIR)/lib/base64.c $(SRC_DIR)/lib/files.c $(SRC_DIR)/lib/embedded_examples.S | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ \
		$(TEST_DIR)/test_host_amd_certs_unit.c \
		$(SRC_DIR)/lib/host_amd_certs.c \
		$(SRC_DIR)/lib/json.c \
		$(SRC_DIR)/lib/base64.c \
		$(SRC_DIR)/lib/files.c \
		$(SRC_DIR)/lib/embedded_examples.S \
		$(LDFLAGS)


# Unit test for snp_report
$(BUILD_DIR)/test_snp_report_unit: $(TEST_DIR)/test_snp_report_unit.c $(SRC_DIR)/lib/snp_report.c $(SRC_DIR)/lib/base64.c $(SRC_DIR)/lib/embedded_examples.S | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ \
		$(TEST_DIR)/test_snp_report_unit.c \
		$(SRC_DIR)/lib/snp_report.c \
		$(SRC_DIR)/lib/base64.c \
		$(SRC_DIR)/lib/embedded_examples.S \
		$(LDFLAGS)


$(BUILD_DIR)/test_uvm_endorsements_unit: $(TEST_DIR)/test_uvm_endorsements_unit.c $(SRC_DIR)/lib/uvm_endorsements.c $(SRC_DIR)/lib/base64.c $(SRC_DIR)/lib/files.c $(SRC_DIR)/lib/embedded_examples.S | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ \
		$(TEST_DIR)/test_uvm_endorsements_unit.c \
		$(SRC_DIR)/lib/uvm_endorsements.c \
		$(SRC_DIR)/lib/base64.c \
		$(SRC_DIR)/lib/files.c \
		$(SRC_DIR)/lib/embedded_examples.S \
		$(LDFLAGS)


clean:
	rm -rf $(BUILD_DIR) $(DEPS_DIR)
