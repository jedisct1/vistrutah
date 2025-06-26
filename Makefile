CC = cc
ARCH := $(shell uname -m)

# Common flags
COMMON_FLAGS = -O3 -Wall -Wextra -std=c11

# Check if portable build is requested
ifdef PORTABLE
    CFLAGS = $(COMMON_FLAGS)
    SOURCES = vistrutah_portable.c vistrutah_common.c
    TEST_EXEC_SUFFIX = _portable
    BENCH_EXEC_SUFFIX = _portable
else
    # Architecture-specific flags
    ifeq ($(ARCH),x86_64)
        # Detect CPU features
        HAS_AVX512 := $(shell gcc -march=native -dM -E - < /dev/null | grep -c AVX512F)
        HAS_VAES := $(shell gcc -march=native -dM -E - < /dev/null | grep -c VAES)
        
        CFLAGS = $(COMMON_FLAGS) -march=native -DVISTRUTAH_INTEL
        SOURCES = vistrutah_intel.c vistrutah_512_intel.c vistrutah_common.c
        TEST_EXEC_SUFFIX = 
        BENCH_EXEC_SUFFIX = 
        
        # Allow disabling AVX-512 for testing
        ifndef NO_AVX512
            ifeq ($(HAS_AVX512),1)
                CFLAGS += -DVISTRUTAH_AVX512
            endif
        endif
        
        ifeq ($(HAS_VAES),1)
            CFLAGS += -DVISTRUTAH_VAES
        endif
    else
        $(error Unsupported architecture: $(ARCH). Only x86_64 is supported)
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
TEST_EXEC = test_vistrutah$(TEST_EXEC_SUFFIX)
BENCH_EXEC = benchmark$(BENCH_EXEC_SUFFIX)

# Default target
all: $(TEST_EXEC) $(BENCH_EXEC)

# Portable build target
portable:
	$(MAKE) PORTABLE=1

# Target to build both implementations
both: all portable

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
	rm -f *.o test_vistrutah test_vistrutah_portable benchmark benchmark_portable

# Run tests
test: $(TEST_EXEC)
	./$(TEST_EXEC)

# Run portable tests
test-portable:
	$(MAKE) PORTABLE=1 test

# Run both tests
test-both: test test-portable

# Run benchmark
bench: $(BENCH_EXEC)
	./$(BENCH_EXEC)

# Run portable benchmark
bench-portable:
	$(MAKE) PORTABLE=1 bench

# Run both benchmarks
bench-both: bench bench-portable

# Show detected architecture
info:
	@echo "Architecture: $(ARCH)"
	@echo "Compiler flags: $(CFLAGS)"
	@echo "Sources: $(SOURCES)"

.PHONY: all clean test bench info portable both test-portable test-both bench-portable bench-both