APPNAME = ehook_tests
CC32 := i686-w64-mingw32-gcc
CXX32 := i686-w64-mingw32-g++
CC64 := x86_64-w64-mingw32-gcc
CXX64 := x86_64-w64-mingw32-g++
CFLAGS = -O3 -Wall -Wextra -Werror
CXXFLAGS = -O3 -Wall -Wextra -Werror
CLINKFLAGS = -static
CXXLINKFLAGS = -static

ARCH ?= 32
ifeq ($(ARCH),64)
    CC := $(CC64)
    CXX := $(CXX64)
    OUTPUT_DIR = build/x64
else
    CC := $(CC32)
    CXX := $(CXX32)
    OUTPUT_DIR = build/x32
endif

ifeq ($(OS),Windows_NT)
    LIBNAME := ehook.lib
else
    ifeq ($(shell uname -s),Linux)
        LIBNAME = libehook.a
    endif
    # ifeq ($(UNAME_S),Darwin)
        # detected_OS := Mac
    # endif
endif

rwc = $(wildcard $1$2) $(foreach d,$(wildcard $1*),$(call rwc,$d/,$2))

COMPONENT_C_SOURCES = $(call rwc,src/,*.c)
COMPONENT_CXX_SOURCES = $(call rwc,src/,*.cpp)
TEST_C_SOURCES = $(call rwc,test/src/,*.c)
TEST_CXX_SOURCES = $(call rwc,test/src/,*.cpp)

COMPONENT_C_OBJECTS = $(patsubst src/%, $(OUTPUT_DIR)/obj/src/%, $(COMPONENT_C_SOURCES:.c=.o))
COMPONENT_CXX_OBJECTS = $(patsubst src/%, $(OUTPUT_DIR)/obj/src/%, $(COMPONENT_CXX_SOURCES:.cpp=.o))
TEST_C_OBJECTS = $(patsubst test/src/%, $(OUTPUT_DIR)/obj/test/src/%, $(TEST_C_SOURCES:.c=.o))
TEST_CXX_OBJECTS = $(patsubst test/src/%, $(OUTPUT_DIR)/obj/test/src/%, $(TEST_CXX_SOURCES:.cpp=.o))

help:
	@echo "Available targets:"
	@echo "  help:  Display this help message (default)"
	@echo "  build: Build the library."
	@echo "  test:  Build tests."
	@echo "    Use ARCH=32 (default) for 32-bit or ARCH=64 for 64-bit."
	@echo "  clean: Remove all build artifacts."
	@echo "    Use ARCH=32 (default) for 32-bit or ARCH=64 for 64-bit."

$(OUTPUT_DIR)/obj/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUTPUT_DIR)/obj/%.o: %.cpp
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OUTPUT_DIR)/lib/$(LIBNAME): $(COMPONENT_C_OBJECTS) $(COMPONENT_CXX_OBJECTS)
	mkdir -p $(dir $@)
	ar rcs $@ $^

$(OUTPUT_DIR)/bin/$(APPNAME): $(TEST_C_OBJECTS) $(TEST_CXX_OBJECTS) $(OUTPUT_DIR)/lib/$(LIBNAME)
	mkdir -p $(dir $@)
	$(CXX) $(TEST_C_OBJECTS) $(TEST_CXX_OBJECTS) -L$(OUTPUT_DIR)/lib -lehook $(CXXLINKFLAGS) -o $@

clean:
	rm -rf build/x32
	rm -rf build/x64

build: $(OUTPUT_DIR)/lib/$(LIBNAME)

test: $(OUTPUT_DIR)/bin/$(APPNAME)

.PHONY: clean help build test
