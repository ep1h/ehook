APPNAME = ehook_tests.exe
CC32 := i686-w64-mingw32-gcc
CXX32 := i686-w64-mingw32-g++
CC64 := x86_64-w64-mingw32-gcc
CXX64 := x86_64-w64-mingw32-g++
CFLAGS = -O3 -Wall -Wextra -Werror
CXXFLAGS = -O3 -Wall -Wextra -Werror
CLINKFLAGS = -static
CXXLINKFLAGS = -static

ARCH ?= x32
OS ?= windows
CFG ?= release

ifeq ($(ARCH),x64)
    CC := $(CC64)
    CXX := $(CXX64)
else
    CC := $(CC32)
    CXX := $(CXX32)
endif

ifeq ($(OS),Windows_NT)
    LIBNAME := ehook.lib
else
    ifeq ($(shell uname -s),Linux)
        LIBNAME = libehook.a
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

help:
	@echo "Usage: make [TARGET] [ARCH]"
	@echo ""
	@echo "TARGET:"
	@echo "build  : Build the library (default)."
	@echo "clean  : Remove all built objects and the resulting binaries."
	@echo "help   : Show this help message."
	@echo ""
	@echo "ARCH:"
	@echo "  x32 : Built 32-bit $(NAME) (default)."
	@echo "  x64 : Built 64-bit $(NAME)."
	@echo ""
	@echo "Examples:"
	@echo "  make           - Build 32-bit $(LIBNAME)(build target and ARCH=x32 are defaults)"
	@echo "  make ARCH=32   - Build 32-bit $(LIBNAME)"
	@echo "  make ARCH=64   - Build 64-bit $(LIBNAME)"
	@echo "  make clean     - Remove all built objects and the resulting binaries."
	@echo "  make help      - Show this help message."

$(BUILD_DIR)/obj/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/obj/%.o: %.cpp
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/lib/$(LIBNAME): $(COMPONENT_C_OBJECTS) $(COMPONENT_CXX_OBJECTS)
	mkdir -p $(dir $@)
	ar rcs $@ $^

$(BUILD_DIR)/bin/$(APPNAME): $(TEST_C_OBJECTS) $(TEST_CXX_OBJECTS) $(BUILD_DIR)/lib/$(LIBNAME)
	mkdir -p $(dir $@)
	$(CXX) $(TEST_C_OBJECTS) $(TEST_CXX_OBJECTS) -L$(BUILD_DIR)/lib -lehook $(CXXLINKFLAGS) -o $@

clean:
	rm -rf build

test: $(BUILD_DIR)/bin/$(APPNAME)
