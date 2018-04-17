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
    std::set<pyrebox_target_ulong> bb_start_offsets;
    pyrebox_target_ulong cr3, monitor_kernel, kernel_iret_addr;

    #define STATS_MAX 5
    pyrebox_target_ulong stats[STATS_MAX];

    void add_bb_start_offset(pyrebox_target_ulong offset) {
        bb_start_offsets.insert(offset);
    }

    pyrebox_target_ulong get_stat(pyrebox_target_ulong idx) {
        return idx < STATS_MAX ? stats[idx] : 0;
    }

    void set_cr3(pyrebox_target_ulong val) {
        cr3 = val;
    }

    void set_monitor_kernel(pyrebox_target_ulong val) {
        monitor_kernel = val;
    }

    void set_kernel_iret_addr(pyrebox_target_ulong val) {
        kernel_iret_addr = val;
    }

    void reset() {
        bb_start_offsets.clear();
        memset(stats, 0, sizeof(stats));
    }

    callback_type_t get_type() {
        return BLOCK_END_CB;
    }

    // Trigger, return 1 if event should be passed to python callback
    int trigger(callback_handle_t handle, callback_params_t params) {
        // Different process
        if (get_pgd(params.block_end_params.cpu) != cr3) {
            ++stats[0];
            return 0;
        }

        if (qemu_is_kernel_running(params.block_end_params.cpu_index) != (int)monitor_kernel) {
            ++stats[1];
            return 0;
        }

        pyrebox_target_ulong eip;
        read_register_convert(params.block_end_params.cpu, RN_EIP, &eip);

        // rep* instruction
        if (params.block_end_params.cur_pc == eip) {
            ++stats[2];
            return 0;
        }

        // Ignore one specific iret control flow transfer, it can return anywhere
        if (params.block_end_params.cur_pc == kernel_iret_addr) {
            ++stats[3];
            return 0;
        }

        if (bb_start_offsets.find(eip) != bb_start_offsets.end()) {
            ++stats[4];
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
