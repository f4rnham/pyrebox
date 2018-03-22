#include <stdio.h>
#include <map>
#include <unordered_set>
#include <set>
#include <list>
#include <string>
#include <Python.h>
extern "C" {
    #include "qemu_glue.h"
    #include "utils.h"
}
#include "callbacks.h"
#include "trigger_helpers.h"

#if defined(TARGET_I386) && !defined(TARGET_X86_64)

extern "C" {
    callback_type_t get_type() {
        return BLOCK_END_CB;
    }

    // Trigger, return 1 if event should be passed to python callback
    int trigger(callback_handle_t handle, callback_params_t params) {
        // Different process
        pyrebox_target_ulong* pgd = (pyrebox_target_ulong*)get_var(handle, "cr3");
        if (get_pgd(params.block_end_params.cpu) != *pgd) {
            return 0;
        }

        pyrebox_target_long* monitor_kernel = (pyrebox_target_long*)get_var(handle, "monitor_kernel");
        if (qemu_is_kernel_running(params.block_end_params.cpu_index) != *monitor_kernel) {
            return 0;
        }

        // rep* instruction
        pyrebox_target_ulong eip;
        read_register_convert(params.block_end_params.cpu, RN_EIP, &eip);
        if (params.block_end_params.cur_pc == eip) {
            return 0;
        }

        return 1;
    }

    void clean(callback_handle_t handle)
    {
        erase_trigger_vars(handle);
    }
}

#endif
