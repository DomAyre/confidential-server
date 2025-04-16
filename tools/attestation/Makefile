# Makefile for tools/attestation

SRC_DIR := src/core
TEST_DIR := test
BUILD_DIR := build
CC := gcc
CFLAGS := -Wall -Wextra -O2 -I$(SRC_DIR)

SRCS := $(shell find $(SRC_DIR) -name '*.c')
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# Exclude print_report.c from OBJS to avoid multiple main definitions
OBJS := $(filter-out $(BUILD_DIR)/print_report.o, $(OBJS))

TEST_SRCS := $(wildcard $(TEST_DIR)/*.c)
TEST_OBJS := $(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/%.test.o,$(TEST_SRCS))

TARGET := $(BUILD_DIR)/attestation_test

LDFLAGS := -lssl -lcrypto

.PHONY: all clean test

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Ensure all subdirectories in BUILD_DIR exist before compiling
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.test.o: $(TEST_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS) $(TEST_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test: $(TARGET)
	./$(TARGET)

clean:
	rm -rf $(BUILD_DIR)
