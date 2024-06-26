/**
 * @file ehook.c
 * @brief Implementation of hooking functionality.
 */
#include "ehook.h"
#include <stdint.h>
#include <inttypes.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif /* MAP_ANONYMOUS */
#include <unistd.h>
#endif /* _WIN32 */

#if defined(_M_IX86) || defined(__i386__)
#define ASM_JMP      0xE9
#define ASM_JMP_SIZE 5
#elif defined(_M_X64) || defined(__x86_64__)
#define ASM_MOV_RAX_ADDR 0xB848
#define ASM_JMP_RAX      0xE0FF
#define ASM_JMP_SIZE     12
#else
#error Unsupported architecture
#endif /* defined(_M_IX86) || defined(__i386__) */
#define ASM_NOP       0x90
#define MIN_HOOK_SIZE ASM_JMP_SIZE

#ifdef _WIN32
#define MemProt DWORD
#else
#define MemProt int
#endif

/**
 * @brief Allocates memory in a process address space.
 *
 * @param[in] size Size of memory to be allocated.
 *
 * @return Pointer to allocated memory or NULL if failed.
 */
static void* allocate_memory_(size_t size);

/**
 * @brief Frees memory allocated by allocate_memory_().
 *
 * @param[in] address Address of memory to be freed.
 * @param[in] size    Size of memory to be freed.
 */
static void free_memory_(void* address, size_t size);

/**
 * @brief Sets memory protection of a memory region.
 *
 * @param[in]  address  Address of a memory region.
 * @param[in]  size     Size of a memory region.
 * @param[in]  prot     New memory protection.
 * @param[out] old_prot Pointer to a variable where old memory protection will
 *                      be stored.
 *
 * @return 1 on success, 0 on failure.
 */
static int protect_memory_(void* address, size_t size, MemProt prot,
                           MemProt* old_prot);
#ifndef _WIN32
/**
 * @brief Gets memory protection of a memory region.
 *
 * @param[in] address Address of a memory region.
 *
 * @return Memory protection of a memory region.
 */
static MemProt get_memory_protection_(void* address);
#endif /* !_WIN32 */

/**
 * @brief Sets jmp hook.
 *
 * @param[in] function_address Address of a function to be hooked.
 * @param[in] hook_address     Address where \p function_address function calls
 *                             should be redirected.
 * @param[in] size             Number of bytes to be overwritten by jmp at
 *                             \p hook_address . Minimum possible value is
 *                             5 for x86 and 12 for x64.
 *
 * @return Address of a trampoline to original function, or NULL on failure.
 */
static void* set_jmp_hook_(void* function_address, void* hook_address,
                           unsigned int size);

/**
 * @brief Removes hook from function at address \p function_address (if exists).
 *
 * @param[in] function_address   Function address on which a hook was previously
 *                               set.
 * @param[in] trampoline_address Address of trampoline to an original function.
 * @param[in] size               Number of bytes overwritten by jmp instruction
 *                               to the hook.
 */
static void unset_jmp_hook_(void* function_address, void* trampoline_address,
                            unsigned int size);

/**
 * @brief Set hook in virtual method table.
 *
 * @param[in] vmt_address   Address of a virtual method table.
 * @param[in] index         Index of a function in a virtual method table.
 * @param[in] hook_address  Address of a function to be called instead of
 *                          original function.
 *
 * @return Address of a function that was previously at \p index in the VMT.
 */
static void* set_vmt_hook_(void* vmt_address, unsigned int index,
                           void* hook_address);

/**
 * @brief Overwrites function call at \p src_address with a call to
 *       \p dst_address .
 *
 * @param[in] src_address   Address of a call instruction's argument to be
 *                          overwritten.
 * @param[in] dst_address   Address of a function to be called instead of
 *                          the overwritten address.
 * @param[in] is_relative   If set to nonzero, \p dst_address will be treated as
 *                          a relative address to \p src_address .
 *
 * @return Original bytes at \p src_address that were overwritten.
 */
static void* overwrite_function_call_(void* src_address, void* dst_address,
                                      char is_relative);

/**
 * @brief Injects bytecode at \p address, relocating overwritten bytes.
 *
 * @param[in] address   Address where bytecode will be injected.
 * @param[in] buf       Bytecode to inject.
 * @param[in] buf_size  Number of bytes to inject.
 * @param[in] jmp_size  Number of bytes to overwrite for the jump detour.
 *
 * @return Address of the allocated buffer containing injected + relocated bytes,
 *         or NULL on failure.
 */
static void* eh_inject_code_(void* address, void* buf, unsigned int buf_size,
                             unsigned int jmp_size);

/**
 * @brief Removes previously injected bytecode at \p address.
 *
 * @param[in] address        Address where bytecode was injected.
 * @param[in] injected_bytes Buffer returned by eh_inject_code_().
 * @param[in] buf_size       Number of injected bytes.
 * @param[in] jmp_size       Number of overwritten bytes.
 */
static void eh_uninject_code_(void* address, void* injected_bytes,
                              unsigned int buf_size, unsigned int jmp_size);

/**
 * @brief Patches bytes at \p address with contents of \p buf.
 *
 * @param[in] address Address to patch.
 * @param[in] buf     Buffer with replacement bytes.
 * @param[in] size    Number of bytes to patch.
 *
 * @return 1 on success, 0 on failure.
 */
static int eh_patch_bytes_(void* address, const void* buf, unsigned int size);

static void* allocate_memory_(size_t size)
{
#ifdef _WIN32

    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE);
#else
    void* result = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    return result == MAP_FAILED ? NULL : result;
#endif /* _WIN32 */
}

static void free_memory_(void* address, size_t size)
{
#ifdef _WIN32
    (void)size;
    VirtualFree(address, 0, MEM_RELEASE);
#else
    munmap(address, size);
#endif /* _WIN32 */
}

#ifndef _WIN32
static MemProt get_memory_protection_(void* address)
{
    MemProt protection = 0;
    uintptr_t addr = (uintptr_t)address;
    char line[256];
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps)
    {
        perror("Failed to open /proc/self/maps");
        return protection;
    }
    while (fgets(line, sizeof(line), maps))
    {
        uintptr_t start, end;
        char perms[5];

        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s", &start, &end,
                   perms) == 3)
        {
            if (addr >= start && addr < end)
            {
                if (perms[0] == 'r')
                    protection |= PROT_READ;
                if (perms[1] == 'w')
                    protection |= PROT_WRITE;
                if (perms[2] == 'x')
                    protection |= PROT_EXEC | PROT_READ;
                break;
            }
        }
    }
    fclose(maps);
    return protection;
}
#endif /* !_WIN32 */

static MemProt get_execute_readwrite_prot_(void)
{
#ifdef _WIN32
    return PAGE_EXECUTE_READWRITE;
#else
    return PROT_EXEC | PROT_READ | PROT_WRITE;
#endif /* _WIN32 */
}

static MemProt get_readwrite_prot_(void)
{
#ifdef _WIN32
    return PAGE_READWRITE;
#else
    return PROT_READ | PROT_WRITE;
#endif /* _WIN32 */
}

static int protect_memory_(void* address, size_t size, MemProt prot,
                           MemProt* old_prot)
{
#ifdef _WIN32
    return VirtualProtect(address, size, prot, old_prot);
#else
    /* Align address to page boundary and adjust size accordingly */
    static size_t page_size = 0;
    if (page_size == 0)
    {
        page_size = (size_t)sysconf(_SC_PAGESIZE);
    }
    uintptr_t aligned = (uintptr_t)address & ~(page_size - 1);
    size_t aligned_size = size + ((uintptr_t)address - aligned);
    void* aligned_address = (void*)aligned;
    *old_prot = get_memory_protection_(aligned_address);
    int result = mprotect(aligned_address, aligned_size, prot);
    return result ? 0 : 1;
#endif /* _WIN32 */
}

static void* set_jmp_hook_(void* function_address, void* hook_address,
                           unsigned int size)
{
#if defined(_M_IX86) || defined(__i386__)
    if (!function_address || !hook_address || size < MIN_HOOK_SIZE)
    {
        return 0;
    }
    uint8_t* trampoline_address =
        (uint8_t*)allocate_memory_(size + ASM_JMP_SIZE);
    if (!trampoline_address)
    {
        return 0;
    }
    memcpy(trampoline_address, function_address, size);
    trampoline_address[size] = ASM_JMP;
    *(unsigned int*)(trampoline_address + size + 1) =
        (uint8_t*)function_address + size - (trampoline_address + size) -
        ASM_JMP_SIZE;
    MemProt cur_prot = 0;
    if (!protect_memory_(function_address, size, get_execute_readwrite_prot_(),
                         &cur_prot))
    {
        free_memory_(trampoline_address, size + ASM_JMP_SIZE);
        return 0;
    }
    memset(function_address, ASM_NOP, size);
    *(uint8_t*)function_address = ASM_JMP;
    *(unsigned int*)((uint8_t*)function_address + 1) =
        (uint8_t*)hook_address - (uint8_t*)function_address - ASM_JMP_SIZE;
    MemProt tmp_prot = 0;
    protect_memory_(function_address, size, cur_prot, &tmp_prot);
    return trampoline_address;
#elif defined(_M_X64) || defined(__x86_64__)
    if (!function_address || !hook_address || size < MIN_HOOK_SIZE)
    {
        return 0;
    }
    uint8_t* trampoline_address =
        (uint8_t*)allocate_memory_(size + ASM_JMP_SIZE);
    if (!trampoline_address)
    {
        return 0;
    }
    /* Copy original bytes in trampoline */
    memcpy(trampoline_address, function_address, size);
    /* Write jmp to original function continuation */
    *(uint16_t*)(trampoline_address + size) = ASM_MOV_RAX_ADDR;
    *(uint64_t*)(trampoline_address + size + 2) =
        (uint64_t)((uint8_t*)function_address + size);
    *(uint16_t*)(trampoline_address + size + 2 + 8) = ASM_JMP_RAX;
    MemProt old_prot = 0;
    if (!protect_memory_(function_address, size, get_execute_readwrite_prot_(),
                         &old_prot))
    {
        free_memory_(trampoline_address, size + ASM_JMP_SIZE);
        return 0;
    }
    memset(function_address, ASM_NOP, size);
    *(uint16_t*)function_address = ASM_MOV_RAX_ADDR;
    *(uint64_t*)((uint8_t*)function_address + 2) = (uint64_t)hook_address;
    *(uint16_t*)((uint8_t*)function_address + 10) = ASM_JMP_RAX;
    MemProt tmp_prot = 0;
    protect_memory_(function_address, size, old_prot, &tmp_prot);
    return trampoline_address;
#endif /* defined(_M_IX86) || defined(__i386__) */
}

static void unset_jmp_hook_(void* function_address, void* trampoline_address,
                            unsigned int size)
{
    if (!function_address || !trampoline_address || size < MIN_HOOK_SIZE)
    {
        return;
    }
    MemProt old_prot = 0;
    if (!protect_memory_(function_address, size, get_execute_readwrite_prot_(),
                         &old_prot))
    {
        return;
    }
    memcpy(function_address, trampoline_address, size);
    MemProt tmp_prot;
    protect_memory_(function_address, size, old_prot, &tmp_prot);
    free_memory_(trampoline_address, size + ASM_JMP_SIZE);
}

static void* set_vmt_hook_(void* vmt_address, unsigned int index,
                           void* hook_address)
{
    if (!vmt_address || !hook_address)
    {
        return 0;
    }
    void** function_address_ptr =
        (void**)((uint8_t*)vmt_address + index * sizeof(void*));
    MemProt old_prot = 0;
    if (!protect_memory_(function_address_ptr, sizeof(void*),
                         get_readwrite_prot_(), &old_prot))
    {
        return 0;
    }
    void* orig_function_address = *function_address_ptr;
    *function_address_ptr = hook_address;
    MemProt tmp_prot = 0;
    protect_memory_(function_address_ptr, sizeof(void*), old_prot, &tmp_prot);
    return orig_function_address;
}

static void* overwrite_function_call_(void* src_address, void* dst_address,
                                      char is_relative)
{
    if (!src_address || !dst_address)
    {
        return NULL;
    }
    void* address = is_relative
                        ? (uint8_t*)((uint8_t*)dst_address -
                                     (uint8_t*)src_address - sizeof(void*))
                        : dst_address;
    void* result = NULL;
    MemProt old_prot = 0;
    if (!protect_memory_(src_address, sizeof(void*),
                         get_execute_readwrite_prot_(), &old_prot))
    {
        return NULL;
    }
    result = *(void**)src_address;
    *(void**)src_address = address;
    MemProt tmp_prot = 0;
    protect_memory_(src_address, sizeof(void*), old_prot, &tmp_prot);
    return result;
}

static void* eh_inject_code_(void* address, void* buf, unsigned int buf_size,
                             unsigned int jmp_size)
{
#if defined(_M_IX86) || defined(__i386__)
    if (!address || !buf || buf_size == 0 || jmp_size < MIN_HOOK_SIZE)
    {
        return NULL;
    }
    uint8_t* injected_bytes =
        (uint8_t*)allocate_memory_(buf_size + jmp_size + ASM_JMP_SIZE);
    if (!injected_bytes)
    {
        return NULL;
    }
    /* Write injected bytes in buf */
    memcpy(injected_bytes, buf, buf_size);
    MemProt cur_prot = 0;
    if (!protect_memory_(address, jmp_size, get_execute_readwrite_prot_(),
                         &cur_prot))
    {
        free_memory_(injected_bytes, buf_size + jmp_size + ASM_JMP_SIZE);
        return NULL;
    }
    /* Write overwritten bytes in buf */
    memcpy(injected_bytes + buf_size, address, jmp_size);

    /* Write jmp to original function continuation in buf */
    injected_bytes[buf_size + jmp_size] = ASM_JMP;
    *(unsigned int*)(injected_bytes + buf_size + jmp_size + 1) =
        (uint8_t*)address + jmp_size - (injected_bytes + buf_size + jmp_size) -
        ASM_JMP_SIZE;

    if (jmp_size > MIN_HOOK_SIZE)
    {
        memset(address, ASM_NOP, jmp_size);
    }
    *(uint8_t*)address = ASM_JMP;

    *(unsigned int*)((uint8_t*)address + 1) =
        (uint8_t*)injected_bytes - (uint8_t*)address - ASM_JMP_SIZE;

    MemProt tmp_prot = 0;
    protect_memory_(address, jmp_size, cur_prot, &tmp_prot);
    return injected_bytes;
#elif defined(_M_X64) || defined(__x86_64__)
    if (!address || !buf || buf_size == 0 || jmp_size < MIN_HOOK_SIZE)
    {
        return NULL;
    }
    uint8_t* injected_bytes =
        (uint8_t*)allocate_memory_(buf_size + jmp_size + ASM_JMP_SIZE);
    if (!injected_bytes)
    {
        return NULL;
    }
    /* Write injected bytes in buf */
    memcpy(injected_bytes, buf, buf_size);
    MemProt cur_prot = 0;
    if (!protect_memory_(address, jmp_size, get_execute_readwrite_prot_(),
                         &cur_prot))
    {
        free_memory_(injected_bytes, buf_size + jmp_size + ASM_JMP_SIZE);
        return NULL;
    }
    /* Write overwritten bytes in buf */
    memcpy(injected_bytes + buf_size, address, jmp_size);

    /* Write jmp to original bytes continuation in buf */
    *(uint16_t*)(&injected_bytes[buf_size + jmp_size]) = ASM_MOV_RAX_ADDR;
    *(uint64_t**)(&injected_bytes[buf_size + jmp_size + 2]) =
        (uint64_t*)((uint8_t*)address + jmp_size);
    *(uint16_t*)(&injected_bytes[buf_size + jmp_size + 2 + 8]) = ASM_JMP_RAX;

    if (jmp_size > MIN_HOOK_SIZE)
    {
        memset(address, ASM_NOP, jmp_size);
    }
    *(uint16_t*)(address) = ASM_MOV_RAX_ADDR;
    *(uint64_t**)(((uint8_t*)address) + 2) = (uint64_t*)(injected_bytes);
    *(uint16_t*)(((uint8_t*)address) + 2 + 8) = ASM_JMP_RAX;

    MemProt tmp_prot = 0;
    protect_memory_(address, jmp_size, cur_prot, &tmp_prot);
    return injected_bytes;
#endif /* defined(_M_IX86) || defined(__i386__) */
}

static void eh_uninject_code_(void* address, void* injected_bytes,
                              unsigned int buf_size, unsigned int jmp_size)
{
    if (!address || !injected_bytes || buf_size == 0 ||
        jmp_size < MIN_HOOK_SIZE)
    {
        return;
    }

    MemProt old_prot = 0;
    if (!protect_memory_(address, jmp_size, get_execute_readwrite_prot_(),
                         &old_prot))
    {
        return;
    }

    memcpy(address, (uint8_t*)injected_bytes + buf_size, jmp_size);
    MemProt tmp_prot;
    protect_memory_(address, jmp_size, old_prot, &tmp_prot);
    free_memory_(injected_bytes, buf_size + jmp_size + ASM_JMP_SIZE);
}

static int eh_patch_bytes_(void* address, const void* buf, unsigned int size)
{
    if (!address || !buf || size == 0)
    {
        return 0;
    }
    MemProt old_prot = 0;
    if (!protect_memory_(address, size, get_execute_readwrite_prot_(),
                         &old_prot))
    {
        return 0;
    }
    memcpy(address, buf, size);
    MemProt tmp_prot;
    protect_memory_(address, size, old_prot, &tmp_prot);
    return 1;
}

void* eh_set_trampoline_hook(void* function_address, void* hook_address,
                             unsigned int size, EhTrampolineType type)
{
    switch (type)
    {
    case EH_TT_TRAMPOLINE_JMP:
    {
        return set_jmp_hook_(function_address, hook_address, size);
    }
    default:
    {
        return NULL;
    }
    }
}

void eh_unset_trampoline_hook(void* function_address, void* trampoline_address,
                              unsigned int size, EhTrampolineType type)
{
    switch (type)
    {
    case EH_TT_TRAMPOLINE_JMP:
    {
        unset_jmp_hook_(function_address, trampoline_address, size);
        break;
    }
    default:
    {
        break;
    }
    }
}

void* eh_set_vmt_hook(void* vmt_address, unsigned int index, void* hook_address)
{
    return set_vmt_hook_(vmt_address, index, hook_address);
}

void eh_unset_vmt_hook(void* vmt_address, unsigned int index,
                       void* original_function_address)
{
    set_vmt_hook_(vmt_address, index, original_function_address);
}

void* eh_overwrite_function_call(void* src_address, void* dst_address,
                                 char is_relative)
{
    return overwrite_function_call_(src_address, dst_address, is_relative);
}

void* eh_inject_code(void* address, void* buf, unsigned int buf_size,
                     unsigned int jmp_size)
{
    return eh_inject_code_(address, buf, buf_size, jmp_size);
}

void eh_uninject_code(void* address, void* injected_bytes,
                      unsigned int buf_size, unsigned int jmp_size)
{
    eh_uninject_code_(address, injected_bytes, buf_size, jmp_size);
}

int eh_patch_bytes(void* address, const void* buf, unsigned int size)
{
    return eh_patch_bytes_(address, buf, size);
}

