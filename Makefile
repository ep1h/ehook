APPNAME = ehook_tests.exe
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

.PHONY: clean help build test
build: $(OUTPUT_DIR)/lib/$(LIBNAME)

help:
	@echo "Usage: make [TARGET] [ARCH]"
	@echo ""
	@echo "TARGET:"
	@echo "build  : Build the library (default)."
	@echo "clean  : Remove all built objects and the resulting binaries.
	@echo "help   : Show this help message."
	@echo ""
	@echo "ARCH:"
	@echo "  32 : Built 32-bit $(NAME) (default)."
	@echo "  64 : Built 64-bit $(NAME)."
	@echo ""
	@echo "Examples:"
	@echo "  make           - Build 32-bit $(LIBNAME)(build target and ARCH=32 are defaults)"
	@echo "  make ARCH=32   - Build 32-bit $(LIBNAME)"
	@echo "  make ARCH=64   - Build 64-bit $(LIBNAME)"
	@echo "  make clean     - Remove all built objects and the resulting binaries."
	@echo "  make help      - Show this help message."

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


test: $(OUTPUT_DIR)/bin/$(APPNAME)
