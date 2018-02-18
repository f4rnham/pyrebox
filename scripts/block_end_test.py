from __future__ import print_function
from ipython_shell import start_shell
from api import CallbackManager

import api
import functools
import volatility.win32.tasks as tasks
from utils import get_addr_space

# Callback manager
cm = None
# Printer
pyrebox_print = None

if __name__ == "__main__":
    print("[*] Loading python module %s" % (__file__))

# Pretty print function, not important
modules = []
def pp_addr(addr, monitored_pgd, refresh = True):
    global modules

    for module in modules:
        if addr >= module['base'] and addr < module['base'] + module['size']:
            return '%s+%x ( %x )' % (module['name'], addr - module['base'], addr)

    # Try again after refreshing module list
    if refresh:
        modules = api.get_module_list(monitored_pgd) + api.get_module_list(0)
        return pp_addr(addr, monitored_pgd, False)

    return '%x' % addr

def block_end(monitored_pgd, cpu_index, cpu, tb, cur_pc, next_pc):
    # Lets ignore kernel monitoring for now, generates mismatches too
    if api.is_kernel_running():
        return

    # Ignore even high addresses, iret instruction from kernel is spamming output
    if cur_pc > 0x80000000:
        return

    # Mismatch found
    if cpu.CR3 != monitored_pgd:
        # Just trying to get to kernel structures for more verbose debug output
        addr_space = get_addr_space(cpu.CR3)
        task = list(tasks.pslist(addr_space))[0]
        task_space = task.get_process_address_space()

        kdbg = tasks.get_kdbg(task_space)
        kpcr = list(kdbg.kpcrs())[0]

        current_thread = kpcr.ProcessorBlock.CurrentThread.dereference_as('_ETHREAD')
        current_image = current_thread.owning_process().ImageFileName
        current_pid = current_thread.Cid.UniqueProcess#UniqueThread

        next_pc = cpu.PC
        pyrebox_print('Incorrectly triggered block end CB for pid: %x, pgd: %x, name: %s' % (current_pid, cpu.CR3, current_image))
        pyrebox_print('%s -> %s' % (pp_addr(cur_pc, cpu.CR3), pp_addr(next_pc, cpu.CR3)))

        #cm.rm_callback('block_end')

def new_proc(pid, pgd, name):
    pyrebox_print("New process created! pid: %x, pgd: %x, name: %s" % (pid, pgd, name))

    cm.rm_callback('new_proc')
    api.start_monitoring_process(pgd)
    cm.add_callback(CallbackManager.BLOCK_END_CB, functools.partial(block_end, pgd), pgd = pgd, name = 'block_end')


def initialize_callbacks(module_hdl, printer):
    global cm
    global pyrebox_print
    pyrebox_print = printer
    pyrebox_print("[*]    Initializing callbacks")
    cm = CallbackManager(module_hdl)

    # Register a process creation callback
    cm.add_callback(CallbackManager.CREATEPROC_CB, new_proc, name = 'new_proc')

    pyrebox_print("[*]    Initialized callbacks")


def clean():
    print("[*]    Cleaning module")
    cm.clean()
    print("[*]    Cleaned module")
