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
        return TLB_EXEC_CB;
    }

    // Trigger, return 1 if event should be passed to python callback
    int trigger(callback_handle_t handle, callback_params_t params) {
        if (params.tlb_exec_params.vaddr >= 0x80000000) {
            return 0;
        }

        pyrebox_target_ulong* pgd = (pyrebox_target_ulong*)get_var(handle, "cr3");
        return get_pgd(params.tlb_exec_params.cpu) == *pgd;
    }

    void clean(callback_handle_t handle)
    {
        erase_trigger_vars(handle);
    }
}

#endif
