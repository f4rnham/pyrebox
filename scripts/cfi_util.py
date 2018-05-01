import api
import vmi
import distorm3
import timeit

# Reload all custom modules
import cfi_globals
reload(cfi_globals)

def get_module_list():
    if cfi_globals.MONITOR_KERNEL:
        return api.get_module_list(cfi_globals.monitored_pgd) + api.get_module_list(0)

    return api.get_module_list(cfi_globals.monitored_pgd)

def get_module_list_ex():
    if cfi_globals.MONITOR_KERNEL:
        vmi.update_modules(0, update_symbols = False)
        return vmi.modules[(0, 0)].values()

    vmi.update_modules(cfi_globals.monitored_pgd, update_symbols = False)
    return vmi.modules[(cfi_globals.monitored_pid, cfi_globals.monitored_pgd)].values()

def print_none(f, *args):
    pass

modules = None
def pp_addr(addr, refresh = True):
    global modules

    if not modules:
        return '%x' % addr

    for module in modules:
        if addr >= module['base'] and addr < module['base'] + module['size']:
            return '%s+%x ( %x )' % (module['name'], addr - module['base'], addr)

    # Try again after refreshing module list
    if refresh:
        modules = get_module_list()
        return pp_addr(addr, False)

    return '%x' % addr

def instr_at(addr):
    try:
        data = api.r_va(cfi_globals.monitored_pgd, addr, cfi_globals.disassembler.MAX_INSTR_SIZE)
        return str(distorm3.DecomposeGenerator(addr, data, distorm3.Decode32Bits, distorm3.DF_STOP_ON_FLOW_CONTROL).next())
    except:
        return 'unknown - error'

class Timer:
    def __init__(self):
        self.total = 0.0
        self.last_start = 0.0

    def start(self):
        self.last_start = timeit.default_timer()

    def stop(self):
        self.total += timeit.default_timer() - self.last_start
        self.last_start = 0

    def __str__(self):
        return str(self.total)
