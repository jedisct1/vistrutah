CC = cc
ARCH := $(shell uname -m)

# Common flags
COMMON_FLAGS = -O3 -Wall -Wextra -std=c11

# Architecture-specific flags
ifeq ($(ARCH),arm64)
    CFLAGS = $(COMMON_FLAGS) -march=armv8-a+crypto -DVISTRUTAH_ARM
    SOURCES = vistrutah.c vistrutah_512.c vistrutah_common.c
else ifeq ($(ARCH),x86_64)
    # Detect CPU features
    HAS_AVX512 := $(shell gcc -march=native -dM -E - < /dev/null | grep -c AVX512F)
    HAS_VAES := $(shell gcc -march=native -dM -E - < /dev/null | grep -c VAES)
    
    CFLAGS = $(COMMON_FLAGS) -march=native -DVISTRUTAH_INTEL
    SOURCES = vistrutah_intel.c vistrutah_512_intel.c vistrutah_common.c
    
    ifeq ($(HAS_AVX512),1)
        CFLAGS += -DVISTRUTAH_AVX512
    endif
    
    ifeq ($(HAS_VAES),1)
        CFLAGS += -DVISTRUTAH_VAES
    endif
endif

LDFLAGS = 

# Source files
TEST_SOURCES = test_vistrutah_portable.c
BENCH_SOURCES = benchmark_portable.c
HEADERS = vistrutah_portable.h

# Object files
OBJECTS = $(SOURCES:.c=.o)
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
BENCH_OBJECTS = $(BENCH_SOURCES:.c=.o)

# Executables
TEST_EXEC = test_vistrutah
BENCH_EXEC = benchmark

# Default target
all: $(TEST_EXEC) $(BENCH_EXEC)

# Build test executable
$(TEST_EXEC): $(OBJECTS) $(TEST_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

# Build benchmark executable
$(BENCH_EXEC): $(OBJECTS) $(BENCH_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

# Pattern rule for object files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean target
clean:
	rm -f $(OBJECTS) $(TEST_OBJECTS) $(BENCH_OBJECTS) $(TEST_EXEC) $(BENCH_EXEC)

# Run tests
test: $(TEST_EXEC)
	./$(TEST_EXEC)

# Run benchmark
bench: $(BENCH_EXEC)
	./$(BENCH_EXEC)

# Show detected architecture
info:
	@echo "Architecture: $(ARCH)"
	@echo "Compiler flags: $(CFLAGS)"

.PHONY: all clean test bench info