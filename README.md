# ehook

Function hooking library for x86/x64. Windows and Linux. C and C++.

## What it does

- Trampoline hooks (JMP-based, original function still callable via trampoline)
- VMT hooks (swap vtable pointers)
- Call-site patching (overwrite a CALL operand)
- Code injection (inject bytecode, overwritten bytes get relocated)
- Byte patching (raw memory writes with automatic protection handling)

## Build

```
make                            # 64-bit Linux release (default)
make ARCH=x32                   # 32-bit Linux release
make CFG=debug                  # 64-bit Linux debug
make CFG=debug ARCH=x32         # 32-bit Linux debug
make OS=windows                 # 64-bit Windows (cross-compile, requires mingw-w64)
make OS=windows ARCH=x32        # 32-bit Windows (cross-compile)
make test                       # build and run tests
make test CFG=debug ARCH=x32    # build and run tests (32-bit debug)
make clean                      # remove all build artifacts
make help                       # show all options
```

## Usage

Link against `libehook.a` and include `ehook.h`. See [ehook.h](src/ehook.h) for details.

```c
// Trampoline hook
void* eh_set_trampoline_hook(void* func, void* hook, unsigned int size, EhTrampolineType type);
void  eh_unset_trampoline_hook(void* func, void* trampoline, unsigned int size, EhTrampolineType type);

// VMT hook
void* eh_set_vmt_hook(void* vmt, unsigned int index, void* hook);
void  eh_unset_vmt_hook(void* vmt, unsigned int index, void* original);

// Overwrite a CALL operand
void* eh_overwrite_function_call(void* src, void* dst, char is_relative);

// Inject bytecode, overwritten bytes get relocated after it
void* eh_inject_code(void* address, void* buf, unsigned int buf_size, unsigned int jmp_size);
void  eh_uninject_code(void* address, void* injected, unsigned int buf_size, unsigned int jmp_size);

// Raw byte patch
int   eh_patch_bytes(void* address, const void* buf, unsigned int size);
```