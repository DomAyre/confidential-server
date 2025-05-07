CC := gcc
CFLAGS := -Wall -Wextra -O2 -Isrc/core
LDFLAGS := -lcrypto -lm

BUILD_DIR := build
SRC_DIR := src/core
TEST_DIR := test

CORE_SRCS := $(wildcard $(SRC_DIR)/*.c)
BINS := $(notdir $(CORE_SRCS:.c=))
BIN_PATHS := $(addprefix $(BUILD_DIR)/,$(BINS))
LIB_SRCS := $(wildcard $(SRC_DIR)/lib/*.c) $(wildcard $(SRC_DIR)/lib/*.S)
TEST_BINARIES := $(BUILD_DIR)/test_base64_unit $(BUILD_DIR)/test_hex_unit $(BUILD_DIR)/test_files_unit $(BUILD_DIR)/test_sha256_unit $(BUILD_DIR)/test_json_unit $(BUILD_DIR)/test_cert_chain_unit $(BUILD_DIR)/test_host_amd_certs_unit $(BUILD_DIR)/test_snp_report_unit

.PHONY: all clean test test_unit lint $(BINS)

all: clean $(BIN_PATHS)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%: $(SRC_DIR)/%.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Phony targets for individual programs
$(BINS): %: $(BUILD_DIR)/%

test: test_unit test_system test_docker
	@echo "All tests passed"

test_unit: clean $(TEST_BINARIES)
	@$(BUILD_DIR)/test_base64_unit
	@$(BUILD_DIR)/test_hex_unit
	@$(BUILD_DIR)/test_files_unit
	@$(BUILD_DIR)/test_sha256_unit
	@$(BUILD_DIR)/test_json_unit
	@$(BUILD_DIR)/test_cert_chain_unit
	@$(BUILD_DIR)/test_host_amd_certs_unit
	@$(BUILD_DIR)/test_snp_report_unit

test_system: clean $(BUILD_DIR)/get_attestation_ccf $(BUILD_DIR)/verify_attestation_ccf
	./build/get_attestation_ccf "example-report-data" \
		| xargs -0 ./build/verify_attestation_ccf \
			--report-data "example-report-data" \
			--security-policy-b64 "$$(cat examples/security_policies/allow_all.rego | base64 -w 0)"

test_docker:
	docker compose up --build --abort-on-container-failure

# Static analysis
lint:
	@echo "Running clang-tidy over C sources..."
	@clang-tidy $(SRC_DIR)/lib/*.c -- -I$(SRC_DIR)

test_aci:
	c-aci-testing target run  . \
		--policy-type "allow_all" \
		--deployment-name "test-aci"

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

$(BUILD_DIR)/test_cert_chain_unit: $(TEST_DIR)/test_cert_chain_unit.c $(SRC_DIR)/lib/cert_chain.c $(SRC_DIR)/lib/json.c $(SRC_DIR)/lib/sha256.c $(SRC_DIR)/lib/snp_report.c $(SRC_DIR)/lib/embedded_examples.S $(SRC_DIR)/lib/base64.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ \
		$(TEST_DIR)/test_cert_chain_unit.c \
		$(SRC_DIR)/lib/cert_chain.c \
		$(SRC_DIR)/lib/json.c \
		$(SRC_DIR)/lib/sha256.c \
		$(SRC_DIR)/lib/snp_report.c \
		$(SRC_DIR)/lib/embedded_examples.S \
		$(SRC_DIR)/lib/base64.c \
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

clean:
	rm -rf $(BUILD_DIR)
