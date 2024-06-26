APPNAME = ehook_tests
CC32 := i686-w64-mingw32-gcc
CXX32 := i686-w64-mingw32-g++
CC64 := x86_64-w64-mingw32-gcc
CXX64 := x86_64-w64-mingw32-g++
CFLAGS = -Wall -Wextra -Werror
CXXFLAGS = -Wall -Wextra -Werror
CLINKFLAGS = -static
CXXLINKFLAGS = -static

ARCH ?= x64
OS ?= linux
CFG ?= release

ifeq ($(OS),linux)
    ifeq ($(ARCH),x64)
        CC := gcc
        CXX := g++
    else
        CC := gcc -m32
        CXX := g++ -m32
    endif
else ifeq ($(OS),windows)
    ifeq ($(ARCH),x64)
        CC := $(CC64)
        CXX := $(CXX64)
    else
        CC := $(CC32)
        CXX := $(CXX32)
    endif
endif

ifeq ($(OS),Windows_NT)
    LIBNAME := ehook.lib
    APPEXT := .exe
else
    ifeq ($(shell uname -s),Linux)
        LIBNAME = libehook.a
        APPEXT :=
    endif
    # ifeq ($(UNAME_S),Darwin)
        # MacOS
    # endif
endif

ifeq ($(CFG),release)
    CFLAGS+= -O3
    CXXFLAGS+= -O3
else
    ifeq ($(CFG),debug)
        CFLAGS+= -g -O0
        CXXFLAGS+= -g -O0
    else
        $(error Invalid build type)
    endif
endif

BUILD_DIR=build/$(CFG)/$(OS)/$(ARCH)

rwc = $(wildcard $1$2) $(foreach d,$(wildcard $1*),$(call rwc,$d/,$2))

COMPONENT_C_SOURCES = $(call rwc,src/,*.c)
COMPONENT_CXX_SOURCES = $(call rwc,src/,*.cpp)
TEST_C_SOURCES = $(call rwc,test/src/,*.c)
TEST_CXX_SOURCES = $(call rwc,test/src/,*.cpp)

COMPONENT_C_OBJECTS = $(patsubst src/%, $(BUILD_DIR)/obj/src/%, $(COMPONENT_C_SOURCES:.c=.o))
COMPONENT_CXX_OBJECTS = $(patsubst src/%, $(BUILD_DIR)/obj/src/%, $(COMPONENT_CXX_SOURCES:.cpp=.o))
TEST_C_OBJECTS = $(patsubst test/src/%, $(BUILD_DIR)/obj/test/src/%, $(TEST_C_SOURCES:.c=.o))
TEST_CXX_OBJECTS = $(patsubst test/src/%, $(BUILD_DIR)/obj/test/src/%, $(TEST_CXX_SOURCES:.cpp=.o))

.PHONY: clean help build test
build: $(BUILD_DIR)/lib/$(LIBNAME)

test: $(BUILD_DIR)/bin/$(APPNAME)$(APPEXT)
	$(BUILD_DIR)/bin/$(APPNAME)$(APPEXT)

help:
	@echo "Usage: make [TARGET] [ARCH=x32|x64] [OS=linux|windows] [CFG=release|debug]"
	@echo ""
	@echo "TARGET:"
	@echo "  build  : Build the library (default)."
	@echo "  test   : Build and run tests."
	@echo "  clean  : Remove all built objects and the resulting binaries."
	@echo "  help   : Show this help message."
	@echo ""
	@echo "ARCH:"
	@echo "  x32 : Build 32-bit $(LIBNAME)."
	@echo "  x64 : Build 64-bit $(LIBNAME) (default)."
	@echo ""
	@echo "OS:"
	@echo "  linux   : Build for Linux (default)."
	@echo "  windows : Cross-compile for Windows (requires mingw-w64)."
	@echo ""
	@echo "CFG:"
	@echo "  release : Optimized build with -O3 (default)."
	@echo "  debug   : Debug build with -g -O0."
	@echo ""
	@echo "Examples:"
	@echo "  make                            - Build 64-bit Linux release $(LIBNAME)"
	@echo "  make ARCH=x32                   - Build 32-bit Linux release $(LIBNAME)"
	@echo "  make CFG=debug                  - Build 64-bit Linux debug $(LIBNAME)"
	@echo "  make CFG=debug ARCH=x32         - Build 32-bit Linux debug $(LIBNAME)"
	@echo "  make OS=windows                 - Cross-compile 64-bit Windows $(LIBNAME)"
	@echo "  make OS=windows ARCH=x32        - Cross-compile 32-bit Windows $(LIBNAME)"
	@echo "  make test                       - Build and run tests (64-bit Linux release)"
	@echo "  make test CFG=debug ARCH=x32    - Build and run tests (32-bit Linux debug)"
	@echo "  make clean                      - Remove all build artifacts"

$(BUILD_DIR)/obj/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Isrc -c $< -o $@

$(BUILD_DIR)/obj/%.o: %.cpp
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -Isrc -c $< -o $@

$(BUILD_DIR)/lib/$(LIBNAME): $(COMPONENT_C_OBJECTS) $(COMPONENT_CXX_OBJECTS)
	mkdir -p $(dir $@)
	ar rcs $@ $^

$(BUILD_DIR)/bin/$(APPNAME)$(APPEXT): $(TEST_C_OBJECTS) $(TEST_CXX_OBJECTS) $(BUILD_DIR)/lib/$(LIBNAME)
	mkdir -p $(dir $@)
	$(CC) $(TEST_C_OBJECTS) $(TEST_CXX_OBJECTS) -L$(BUILD_DIR)/lib -lehook $(CLINKFLAGS) -o $@

clean:
	rm -rf build
