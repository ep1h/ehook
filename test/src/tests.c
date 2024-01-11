
#include "../../src/ehook.h"
#include <stdint.h>
#ifdef __cplusplus
#include <cassert>
#else
#include <assert.h>
#endif /* __cplusplus */

#if defined(_MSC_VER)
#define CC_CDECL        __cdecl
#define CC_STDCALL      __stdcall
#define CC_FASTCALL     __fastcall
#define CC_THISCALL     __fastcall
#define NOINLINE        __declspec(noinline)
#define NAKED           __declspec(naked)
#define ASM_INLINE(...) __asm { __VA_ARGS__ }
#elif defined(__GNUC__) || defined(__clang__)
#define CC_CDECL        __attribute__((cdecl))
#define CC_STDCALL      __attribute__((stdcall))
#define CC_FASTCALL     __attribute__((fastcall))
#define CC_THISCALL     __attribute__((fastcall))
#define NOINLINE        __attribute__((noinline))
#define NAKED           __attribute__((naked))
#define Q_(...)         #__VA_ARGS__
#define QUOTE(...)      Q_(__VA_ARGS__)
#define ASM_INLINE(...) asm(QUOTE(__VA_ARGS__));
#else
#error "Unknown compiler"
#endif /* _MSC_VER */

#if defined(_M_IX86) || defined(__i386__)
#define MIN_HOOK_SIZE 5
#define ADDR32(addr)  ((void*)addr)
#elif defined(_M_X64) || defined(__x86_64__)
#define MIN_HOOK_SIZE 12
#define ADDR32(addr)                                                           \
    ((void*)(((uint64_t)(uint32_t)(addr) << 32) | (uint32_t)(addr)))
#else
#error Unsupported architecture
#endif /* defined(_M_IX86) || defined(__i386__) */


static void test_eh_set_trampoline_hook_invalid_args_(void)
{
    void* func_orig_emul = ADDR32(0x12345678);
    void* func_hook_emul = ADDR32(0x87654321);

    assert(eh_set_trampoline_hook(NULL, (void*)func_hook_emul, 5,
                                  EH_TT_TRAMPOLINE_JMP) == NULL);
    assert(eh_set_trampoline_hook((void*)func_orig_emul, NULL, 5,
                                  EH_TT_TRAMPOLINE_JMP) == NULL);
    assert(eh_set_trampoline_hook((void*)func_orig_emul, NULL, 4,
                                  EH_TT_TRAMPOLINE_JMP) == NULL);
}

#if defined(_M_IX86) || defined(__i386__)
static void test_eh_set_trampoline_hook_(void)
{
    uint8_t func_orig_bytes[0xFF];
    uint8_t func_orig_emul[0x50];
    uint8_t func_hook_emul[0x50];
    for (size_t i = 0; i < sizeof(func_orig_emul); i++)
    {
        func_orig_bytes[i] = (uint8_t)i;
        func_orig_emul[i] = func_orig_bytes[i];
    }
    for (size_t i = 0; i < sizeof(func_hook_emul); i++)
    {
        func_hook_emul[i] = (uint8_t)i;
    }

    for (size_t hook_size = MIN_HOOK_SIZE; hook_size < MIN_HOOK_SIZE * 2;
         hook_size++)
    {
        void* trampoline =
            eh_set_trampoline_hook((void*)func_orig_emul, (void*)func_hook_emul,
                                   hook_size, EH_TT_TRAMPOLINE_JMP);

        /* Check trampoline bytes */
        assert(trampoline != NULL);

        for (size_t i = 0; i < hook_size; i++)
        {
            assert(((uint8_t*)trampoline)[i] == ((uint8_t*)func_orig_bytes)[i]);
        }
        assert(((uint8_t*)trampoline)[hook_size] == 0xE9);

        void* jump_addr_in_trampoline =
            *(void**)((uint8_t*)trampoline + hook_size + 1);
        void* orig_function_continuation_rel_addr =
            (void*)(((uint8_t*)func_orig_emul + hook_size) -
                    ((uint8_t*)trampoline + hook_size) - 5);
        assert(jump_addr_in_trampoline == orig_function_continuation_rel_addr);

        /* Check original function bytes */
        assert(func_orig_emul[0] == 0xE9);
        void* trampoline_rel_addr =
            (void*)((uint8_t*)func_hook_emul - (uint8_t*)func_orig_emul - 5);
        assert(*(void**)((uint8_t*)func_orig_emul + 1) == trampoline_rel_addr);

        /* Check nops (if exists) */
        size_t nops_count = hook_size - 5;
        for (size_t i = 0; i < nops_count; i++)
        {
            assert(func_orig_emul[i + 5] == 0x90);
        }

        eh_unset_trampoline_hook((void*)func_orig_emul, trampoline, hook_size,
                                 EH_TT_TRAMPOLINE_JMP);

        /* Check original function bytes after removing hook */
        for (size_t i = 0; i < sizeof(func_orig_emul); i++)
        {
            assert(func_orig_emul[i] == func_orig_bytes[i]);
        }
    }
}
#elif defined(_M_X64) || defined(__x86_64__)
static void test_eh_set_trampoline_hook_(void)
{
    uint8_t func_orig_bytes[0xFF];
    uint8_t func_orig_emul[0x50];
    uint8_t func_hook_emul[0x50];
    for (size_t i = 0; i < sizeof(func_orig_emul); i++)
    {
        func_orig_bytes[i] = (uint8_t)i;
        func_orig_emul[i] = func_orig_bytes[i];
    }
    for (size_t i = 0; i < sizeof(func_hook_emul); i++)
    {
        func_hook_emul[i] = (uint8_t)i;
    }

    for (size_t hook_size = MIN_HOOK_SIZE; hook_size < MIN_HOOK_SIZE * 2;
         hook_size++)
    {
        void* trampoline =
            eh_set_trampoline_hook((void*)func_orig_emul, (void*)func_hook_emul,
                                   hook_size, EH_TT_TRAMPOLINE_JMP);

        /* Check trampoline bytes */
        assert(trampoline != NULL);

        for (size_t i = 0; i < hook_size; i++)
        {
            assert(((uint8_t*)trampoline)[i] == ((uint8_t*)func_orig_bytes)[i]);
        }
        assert(*(uint16_t*)((uint8_t*)trampoline + hook_size) ==
               0xB848); /* ASM_MOV_RAX_ADDR */

        assert(*(uint16_t*)((uint8_t*)trampoline + hook_size + 2 + 8) ==
               0xE0FF); /* ASM_JMP_RAX */

        /* Check original function bytes */
        assert(*(uint16_t*)func_orig_emul == 0xB848); /* ASM_MOV_RAX_ADDR */
        assert(*(void**)((uint8_t*)func_orig_emul + 2) ==
               func_hook_emul); /* ASM_JMP_RAX */
        assert(*(uint16_t*)((uint8_t*)func_orig_emul + 2 + 8) ==
               0xE0FF); /* ASM_JMP_RAX */

        /* Check nops (if exists) */
        size_t nops_count = hook_size - MIN_HOOK_SIZE;
        for (size_t i = 0; i < nops_count; i++)
        {
            assert(func_orig_emul[i + MIN_HOOK_SIZE] == 0x90);
        }

        eh_unset_trampoline_hook((void*)func_orig_emul, trampoline, hook_size,
                                 EH_TT_TRAMPOLINE_JMP);

        /* Check original function bytes after removing hook */
        for (size_t i = 0; i < sizeof(func_orig_emul); i++)
        {
            assert(func_orig_emul[i] == func_orig_bytes[i]);
        }
    }
}

#else
#error "Unknown compiler"
#endif /* _MSC_VER */

static void test_eh_set_vmt_hook_invalid_args_(void)
{
    void* vmt_emul[] = {ADDR32(0xAAAAAAAA), ADDR32(0xBBBBBBBB),
                        ADDR32(0xCCCCCCCC), ADDR32(0xDDDDDDDD),
                        ADDR32(0xEEEEEEEE), ADDR32(0xFFFFFFFF)};
    assert(eh_set_vmt_hook(NULL, 0, ADDR32(0x10000001)) == NULL);
    assert(eh_set_vmt_hook((void*)vmt_emul, 0, 0) == NULL);
    assert(vmt_emul[0] == ADDR32(0xAAAAAAAA));
    assert(vmt_emul[1] == ADDR32(0xBBBBBBBB));
    assert(vmt_emul[2] == ADDR32(0xCCCCCCCC));
    assert(vmt_emul[3] == ADDR32(0xDDDDDDDD));
    assert(vmt_emul[4] == ADDR32(0xEEEEEEEE));
    assert(vmt_emul[5] == ADDR32(0xFFFFFFFF));
    eh_unset_vmt_hook(NULL, 0, ADDR32(0x10000001));
    eh_unset_vmt_hook(NULL, 3, ADDR32(0x10000001));
    eh_unset_vmt_hook(NULL, 5, ADDR32(0x10000001));
    assert(vmt_emul[0] == ADDR32(0xAAAAAAAA));
    assert(vmt_emul[1] == ADDR32(0xBBBBBBBB));
    assert(vmt_emul[2] == ADDR32(0xCCCCCCCC));
    assert(vmt_emul[3] == ADDR32(0xDDDDDDDD));
    assert(vmt_emul[4] == ADDR32(0xEEEEEEEE));
    assert(vmt_emul[5] == ADDR32(0xFFFFFFFF));
}


static void test_eh_set_vmt_hook_(void)
{
    void* vmt_emul[] = {ADDR32(0xAAAAAAAA), ADDR32(0xBBBBBBBB),
                        ADDR32(0xCCCCCCCC), ADDR32(0xDDDDDDDD),
                        ADDR32(0xEEEEEEEE), ADDR32(0xFFFFFFFF)};

    assert(vmt_emul[0] == ADDR32(0xAAAAAAAA));
    assert(vmt_emul[1] == ADDR32(0xBBBBBBBB));
    assert(vmt_emul[2] == ADDR32(0xCCCCCCCC));
    assert(vmt_emul[3] == ADDR32(0xDDDDDDDD));
    assert(vmt_emul[4] == ADDR32(0xEEEEEEEE));
    assert(vmt_emul[5] == ADDR32(0xFFFFFFFF));

    assert(eh_set_vmt_hook((void*)vmt_emul, 0, ADDR32(0x10000001)) ==
           ADDR32(0xAAAAAAAA));
    assert(eh_set_vmt_hook((void*)vmt_emul, 1, ADDR32(0x11111111)) ==
           ADDR32(0xBBBBBBBB));
    assert(eh_set_vmt_hook((void*)vmt_emul, 3, ADDR32(0x33333333)) ==
           ADDR32(0xDDDDDDDD));
    assert(eh_set_vmt_hook((void*)vmt_emul, 5, ADDR32(0x33333333)) ==
           ADDR32(0xFFFFFFFF));

    assert(vmt_emul[0] == ADDR32(0x10000001));
    assert(vmt_emul[1] == ADDR32(0x11111111));
    assert(vmt_emul[2] == ADDR32(0xCCCCCCCC));
    assert(vmt_emul[3] == ADDR32(0x33333333));
    assert(vmt_emul[4] == ADDR32(0xEEEEEEEE));
    assert(vmt_emul[5] == ADDR32(0x33333333));

    eh_unset_vmt_hook((void*)vmt_emul, 0, ADDR32(0xAAAAAAAA));
    eh_unset_vmt_hook((void*)vmt_emul, 1, ADDR32(0xBBBBBBBB));
    eh_unset_vmt_hook((void*)vmt_emul, 3, ADDR32(0xDDDDDDDD));
    eh_unset_vmt_hook((void*)vmt_emul, 5, ADDR32(0xFFFFFFFF));

    assert(vmt_emul[0] == ADDR32(0xAAAAAAAA));
    assert(vmt_emul[1] == ADDR32(0xBBBBBBBB));
    assert(vmt_emul[2] == ADDR32(0xCCCCCCCC));
    assert(vmt_emul[3] == ADDR32(0xDDDDDDDD));
    assert(vmt_emul[4] == ADDR32(0xEEEEEEEE));
    assert(vmt_emul[5] == ADDR32(0xFFFFFFFF));
}
void test_eh_overwrite_function_call_invalid_args_(void)
{
    void* code_bytes_emul = ADDR32(0x12345678);
    void* code_bytes_ptr = (void*)&code_bytes_emul;

    void* dst = (void*)0xABCDFE9F;
    assert(eh_overwrite_function_call(code_bytes_emul, 0, 0) == 0);
    assert(eh_overwrite_function_call(code_bytes_emul, 0, 1) == 0);
    assert(eh_overwrite_function_call(0, dst, 0) == 0);
    assert(eh_overwrite_function_call(0, dst, 1) == 0);
    assert(code_bytes_ptr == (void*)&code_bytes_emul);
    assert(code_bytes_emul == ADDR32(0x12345678));
}

void test_eh_overwrite_function_call_(void)
{
    uint8_t code_bytes_emul[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};

    void* dst = ADDR32(0x89ABCDEF);
    void* function_call_instruction_address = code_bytes_emul + 22;
    void* orig = *(void**)function_call_instruction_address;

    /* Absolute */
    assert(eh_overwrite_function_call(function_call_instruction_address, dst,
                                      0) == orig);
    size_t offset = 0;
    for (; offset < 22; offset++)
    {
        assert((int)(code_bytes_emul[offset]) == offset);
    }
    assert(*(void**)(&code_bytes_emul[offset]) == dst);
    offset += sizeof(void*);
    for (; offset < sizeof(code_bytes_emul); offset++)
    {
        assert(code_bytes_emul[offset] == offset);
    }
    assert(eh_overwrite_function_call(function_call_instruction_address, orig,
                                      0) == dst);
    for (size_t i = 0; i < sizeof(code_bytes_emul); i++)
    {
        assert(code_bytes_emul[i] == i);
    }

    /* Relative */
    orig = *(void**)function_call_instruction_address;
    void* relative_address =
        (void*)((uint8_t*)dst - (uint8_t*)function_call_instruction_address -
                sizeof(void*));
    assert(eh_overwrite_function_call(function_call_instruction_address, dst,
                                      1) == orig);
    offset = 0;
    for (; offset < 22; offset++)
    {
        assert(code_bytes_emul[offset] == offset);
    }
    assert(*(void**)(&code_bytes_emul[offset]) == relative_address);
    offset += sizeof(void*);
    for (; offset < sizeof(code_bytes_emul); offset++)
    {
        assert(code_bytes_emul[offset] == offset);
    }
    assert(eh_overwrite_function_call(function_call_instruction_address, orig,
                                      0) == relative_address);
    for (size_t i = 0; i < sizeof(code_bytes_emul); i++)
    {
        assert(code_bytes_emul[i] == i);
    }
}


void test_eh_inject_code_invalid_args_(void)
{
    uint8_t code_bytes_orig[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};

    uint8_t code_bytes_emul[sizeof(code_bytes_orig)];
    for (size_t i = 0; i < sizeof(code_bytes_orig); i++)
    {
        code_bytes_emul[i] = code_bytes_orig[i];
    }

    uint8_t injected_bytes[] = {0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0x90, 0xF5};
    unsigned int jmp_size = 7;
    assert(eh_inject_code(0, injected_bytes, sizeof(injected_bytes),
                          jmp_size) == NULL);
    assert(eh_inject_code(code_bytes_emul, 0, sizeof(injected_bytes),
                          jmp_size) == NULL);
    assert(eh_inject_code(code_bytes_emul, injected_bytes, 0, jmp_size) ==
           NULL);
#if defined(_M_IX86) || defined(__i386__)
    assert(eh_inject_code(code_bytes_emul, injected_bytes,
                          sizeof(injected_bytes), 4) == NULL);
#elif defined(_M_X64) || defined(__x86_64__)
    assert(eh_inject_code(code_bytes_emul, injected_bytes,
                          sizeof(injected_bytes), 11) == NULL);
#endif
    eh_uninject_code(0, code_bytes_emul, sizeof(injected_bytes), jmp_size);
    eh_uninject_code(code_bytes_emul, 0, sizeof(injected_bytes), jmp_size);
    eh_uninject_code(code_bytes_emul, code_bytes_emul, 0, jmp_size);
#if defined(_M_IX86) || defined(__i386__)
    eh_uninject_code(code_bytes_emul, code_bytes_emul, sizeof(injected_bytes),
                     4);
#elif defined(_M_X64) || defined(__x86_64__)
    eh_uninject_code(code_bytes_emul, code_bytes_emul, sizeof(injected_bytes),
                     11);
#endif
}

#if defined(_M_IX86) || defined(__i386__)
void test_eh_inject_code_(void)
{
    uint8_t code_bytes_orig[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};

    uint8_t code_bytes_emul[sizeof(code_bytes_orig)];
    for (size_t i = 0; i < sizeof(code_bytes_orig); i++)
    {
        code_bytes_emul[i] = code_bytes_orig[i];
    }

    uint8_t injected_bytes[] = {0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0x90, 0xF5};
    unsigned int jmp_size = 7;
    uint8_t* injected_buf = eh_inject_code(code_bytes_emul, injected_bytes,
                                           sizeof(injected_bytes), jmp_size);
    /* Test bytes */
    assert(injected_buf != 0);
    assert(code_bytes_emul[0] == 0xE9); /* Jmp */
    void* jmp_rel_addr =
        (void*)((uint8_t*)injected_buf - (uint8_t*)code_bytes_emul - 5);
    assert(*(void**)((uint8_t*)code_bytes_emul + 1) == jmp_rel_addr); /* Addr */
    for (size_t i = 5; i < jmp_size; i++)
    {
        assert(code_bytes_emul[i] == 0x90); /* Nops */
    }

    /* Test injected bytes */
    for (size_t i = 0; i < sizeof(injected_bytes) + jmp_size; i++)
    {
        if (i < sizeof(injected_bytes))
        {
            /* Injected bytes */
            assert(injected_buf[i] == injected_bytes[i]);
        }
        else
        {
            /* Original bytes */
            assert(injected_buf[i] ==
                   ((uint8_t*)code_bytes_orig)[i - sizeof(injected_bytes)]);
        }
    }
    /* Jmp to orig place */
    assert(injected_buf[sizeof(injected_bytes) + jmp_size] == 0xE9);
    jmp_rel_addr =
        (uint8_t*)(code_bytes_emul + jmp_size -
                   (injected_buf + sizeof(injected_bytes) + jmp_size) - 5);
    assert(
        *(uint32_t**)(&injected_buf[sizeof(injected_bytes) + jmp_size + 1]) ==
        jmp_rel_addr);

    eh_uninject_code(code_bytes_emul, injected_buf, sizeof(injected_bytes),
                     jmp_size);
    for (size_t i = 0; i < sizeof(code_bytes_emul); i++)
    {
        assert(code_bytes_emul[i] == code_bytes_orig[i]);
    }
}
#elif defined(_M_X64) || defined(__x86_64__)
void test_eh_inject_code_(void)
{
    uint8_t code_bytes_orig[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};

    uint8_t code_bytes_emul[sizeof(code_bytes_orig)];
    for (size_t i = 0; i < sizeof(code_bytes_orig); i++)
    {
        code_bytes_emul[i] = code_bytes_orig[i];
    }

    uint8_t injected_bytes[] = {0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0x90, 0xF5};
    unsigned int jmp_size = 17;
    uint8_t* injected_buf = eh_inject_code(code_bytes_emul, injected_bytes,
                                           sizeof(injected_bytes), jmp_size);
    /* Test bytes */
    assert(injected_buf != 0);
    assert(*(uint16_t*)code_bytes_emul == 0xB848); /* MOV RAX */
    assert(*(uint64_t**)((uint8_t*)code_bytes_emul + 2) ==
           (uint64_t*)injected_buf);                         /* Addr */
    assert(*(uint16_t*)(code_bytes_emul + 2 + 8) == 0xE0FF); /*JMP RAX */

    for (size_t i = 12; i < jmp_size; i++)
    {
        assert(code_bytes_emul[i] == 0x90); /* Nops */
    }

    /* Test injected bytes */
    for (size_t i = 0; i < sizeof(injected_bytes) + jmp_size; i++)
    {
        if (i < sizeof(injected_bytes))
        {
            /* Injected bytes */
            assert(injected_buf[i] == injected_bytes[i]);
        }
        else
        {
            /* Original bytes */
            assert(injected_buf[i] ==
                   ((uint8_t*)code_bytes_orig)[i - sizeof(injected_bytes)]);
        }
    }
    /* Jmp to orig place */
    assert(*(uint16_t*)(injected_buf + sizeof(injected_bytes) + jmp_size) ==
           0xB848); /* MOV RAX */
    assert(*(void**)(injected_buf + sizeof(injected_bytes) + jmp_size + 2) ==
           code_bytes_emul + jmp_size); /* Addr */
    assert(*(uint16_t*)(injected_buf + sizeof(injected_bytes) + jmp_size + 2 +
                        8) == 0xE0FF); /*JMP RAX */

    eh_uninject_code(code_bytes_emul, injected_buf, sizeof(injected_bytes),
                     jmp_size);
    for (size_t i = 0; i < sizeof(code_bytes_emul); i++)
    {
        assert(code_bytes_emul[i] == code_bytes_orig[i]);
    }
}
#else
#error "Unknown compiler"
#endif /* _MSC_VER */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    test_eh_set_trampoline_hook_invalid_args_();
    test_eh_set_trampoline_hook_();

    test_eh_set_vmt_hook_();
    test_eh_set_vmt_hook_invalid_args_();

    test_eh_overwrite_function_call_();
    test_eh_overwrite_function_call_invalid_args_();

    test_eh_inject_code_invalid_args_();
    test_eh_inject_code_();

    return 0;
}
