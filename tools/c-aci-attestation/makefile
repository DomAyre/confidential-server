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
TEST_BINARY := $(BUILD_DIR)/test_base64_unit

.PHONY: all clean test test_unit $(BINS)

all: clean $(BIN_PATHS)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%: $(SRC_DIR)/%.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Phony targets for individual programs
$(BINS): %: $(BUILD_DIR)/%

test: test_unit test_system test_docker
	@echo "All tests passed"

test_unit: $(TEST_BINARY)
	@$(TEST_BINARY)

test_system: $(BUILD_DIR)/get_attestation_ccf $(BUILD_DIR)/verify_attestation_ccf
	./build/get_attestation_ccf "example-report-data" \
		| xargs -0 ./build/verify_attestation_ccf \
			--report-data "example-report-data" \
			--security-policy-b64 "$$(cat examples/security_policies/allow_all.rego | base64 -w 0)"

test_docker:
	docker compose up --build --abort-on-container-failure

test_aci:
	c-aci-testing target run  . \
		--policy-type "allow_all" \
		--deployment-name "test-aci"

$(TEST_BINARY): | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ \
		$(TEST_DIR)/test_base64_unit.c \
		$(SRC_DIR)/lib/base64.c \
		$(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)
