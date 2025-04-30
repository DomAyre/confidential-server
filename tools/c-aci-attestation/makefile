CC := gcc
CFLAGS := -Wall -Wextra -O2 -Isrc/core
LDFLAGS := -lcrypto

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

test: test_unit

test_unit: $(TEST_BINARY)
	@$(TEST_BINARY)

$(TEST_BINARY): | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ \
		$(TEST_DIR)/test_base64_unit.c \
		$(SRC_DIR)/lib/base64.c \
		$(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)
