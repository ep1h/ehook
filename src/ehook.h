/**
 * @file ehook.h
 * @brief API for function hooking mechanisms.
 */
#ifndef EHOOK_H_
#define EHOOK_H_

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

typedef enum EhTrampolineType
{
    EH_TT_TRAMPOLINE_JMP,
} EhTrampolineType;

/**
 * @brief Sets a trampoline hook on a function. If successful, all subsequent
 *        calls to the function at \p ​function_address will be redirected to
 *        \p hook_address .
 *
 * @param[in] function_address Address of the function to hook.
 * @param[in] hook_address     Address where the function \p function_address
 *                             should redirect calls.
 * @param[in] size             Number of bytes to be overwritten during the
 *                             transition to \p hook_address. Minimum values are
 *                             5 bytes for x86 and 12 bytes for x64
 *                             architectures.
 * @param[in] type             Type of transition to trampoline.
 *
 * @return Address of a trampoline to the original function if successful. Null
 *         if failed.
 */
void* eh_set_trampoline_hook(void* function_address, void* hook_address,
                             unsigned int size, EhTrampolineType type);

/**
 * @brief Removes a previously set trampoline hook on a function.
 *
 * @param[in] function_address   Address of the function where the hook was set.
 * @param[in] trampoline_address Address of the trampoline to the original
 *                               function.
 * @param[in] size               Number of bytes previously overwritten.
 * @param[in] type               Type of transition to trampoline.
 */
void eh_unset_trampoline_hook(void* function_address, void* trampoline_address,
                              unsigned int size, EhTrampolineType type);

/**
 * @brief Sets a VMT hook on a function. If successful, subsequent calls to the
 *        function at \p ​vmt_address[index] will redirect to \p hook_address
 *
 * @param[in] vmt_address   Address of the VMT to hook.
 * @param[in] index         Index of the function within the VMT to hook.
 * @param[in] hook_address  Address where the function at \p vmt_address[index]
 *                          should redirect calls.
 *
 * @return Address of the original VMT entry if successful. Null if fail.
 */
void* eh_set_vmt_hook(void* vmt_address, unsigned int index,
                      void* hook_address);

/**
 * @brief Removes a previously set VMT hook on a function.
 *
 * @param[in] vmt_address   Address of the VMT from which to unhook.
 * @param[in] index         Index of the function within the VMT to unhook.
 * @param[in] original_function_address  Address of the original function.
 */
void eh_unset_vmt_hook(void* vmt_address, unsigned int index,
                       void* original_function_address);

/**
 * @brief Replaces the address of a function within a call (or similar)
 *        instruction with a new address.
 *
 * @param[in] src_address Address of the function call to overwrite.
 * @param[in] dst_address Address of the new function to call instead of
 *                        \p src_address.
 * @param[in] is_relative Indicates whether the function call uses a relative or
 *                        absolute address.
 *
 * @return Address of the original function if successful. Null if failed.
 */
void* eh_overwrite_function_call(void* src_address, void* dst_address,
                                 char is_relative);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* EHOOK_H_ */
