import pefile
import functools
import api
from api import CallbackManager, BP

# Reload all custom modules
import cfi_globals
reload(cfi_globals)

def on_ep_context_change(proc_name, callback, old_pgd, new_pgd):
    if cfi_globals.monitored_pgd == new_pgd:
        try:
            m = next((m for m in api.get_module_list(cfi_globals.monitored_pgd) if m['name'] == proc_name), None)
            image_base_addr = m['base']
            pe = pefile.PE(data = api.r_va(cfi_globals.monitored_pgd, image_base_addr, 0x1000))
            ep_addr = image_base_addr + pe.OPTIONAL_HEADER.AddressOfEntryPoint

            cfi_globals.ep_bp = BP(ep_addr, cfi_globals.monitored_pgd, typ = BP.EXECUTION, func = callback)
            cfi_globals.ep_bp.enable()
            cfi_globals.pyrebox_print('Waiting for EP %x, base %x' % (ep_addr, image_base_addr))
            cfi_globals.cm.rm_callback('on_ep_' + proc_name)
        except:
            pass

def on_ep_new_proc(proc_name, callback, pid, pgd, name):
    if proc_name.startswith(name):
        cfi_globals.pyrebox_print('Found process! pid: %x, pgd: %x, name: %s' % (pid, pgd, name))
        cfi_globals.cm.rm_callback('on_ep_' + proc_name)

        cfi_globals.monitored_pgd = pgd
        cfi_globals.monitored_pid = pid
        api.start_monitoring_process(cfi_globals.monitored_pgd)

        cfi_globals.cm.add_callback(CallbackManager.CONTEXTCHANGE_CB, functools.partial(on_ep_context_change, proc_name, callback), name = 'on_ep_' + proc_name)

def on_ep(proc_name, callback):
    callback = functools.partial(callback, proc_name)
    cfi_globals.cm.add_callback(CallbackManager.CREATEPROC_CB, functools.partial(on_ep_new_proc, proc_name, callback), name = 'on_ep_' + proc_name)

    cfi_globals.pyrebox_print('Waiting for process %s to start' % proc_name)
