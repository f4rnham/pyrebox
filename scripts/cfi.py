from __future__ import print_function
import api
import os
import ntpath
import binascii
import struct
import distorm3
import functools
from ctypes import *

from collections import deque, defaultdict

from api import CallbackManager, BP
from utils import get_addr_space
from ipython_shell import start_shell

import volatility.obj as obj
import volatility.win32.tasks as tasks
from volatility.renderers.basic import Address, Hex

# Reload all custom modules
import cfi_globals
reload(cfi_globals)
import cfi_on_ep
reload(cfi_on_ep)
import cfi_util
reload(cfi_util)
import cfi_cli
reload(cfi_cli)

from cfi_on_ep import *
from cfi_util import *
from cfi_cli import *

PAGE_MASK = 0xFFFFF000
PAGE_SIZE = 0x00001000
##DEBUG_ENABLE_SYMS = []
##THROW_ON_QUEUE = []

pyrebox_print = None
debug_print = None

if __name__ == '__main__':
    print('[*] Loading python module %s' % (__file__))

def initialize_callbacks(module_hdl, printer):
    global pyrebox_print
    global debug_print

    # Initialize printer function
    pyrebox_print = printer
    cfi_globals.pyrebox_print = printer
    ##debug_print = printer
    debug_print = print_none
    pyrebox_print('[*]    Initializing callbacks')

    # Initialize the callback manager
    cfi_globals.cm = CallbackManager(module_hdl)

    if cfi_globals.MONITOR_KERNEL or cfi_globals.MONITORED_PROC_NAME:
        initialize_monitoring()

    pyrebox_print('[*]    Initialized callbacks')

def initialize_monitoring():
    if cfi_globals.MONITOR_KERNEL:
        cfi_globals.MONITORED_PROC_NAME = 'System'

    for proc in api.get_process_list():
        if proc['name'] == cfi_globals.MONITORED_PROC_NAME:
            cfi_globals.monitored_pgd = proc['pgd']
            cfi_globals.monitored_pid = proc['pid']
            api.start_monitoring_process(cfi_globals.monitored_pgd)
            disasm(proc['name'], None, None)

    # Process not running, wait for start
    if cfi_globals.monitored_pgd == None:
        on_ep(cfi_globals.MONITORED_PROC_NAME, disasm)

def clean():
    print('[*]    Cleaning module')
    cfi_globals.cm.clean()
    print('[*]    Cleaned module')

def remove_proc(pid, pgd, name):
    if pgd == cfi_globals.monitored_pgd and pid == cfi_globals.monitored_pid:
        pyrebox_print('Monitored process %s exited' % name)
        cfi_globals.cm.rm_callback('remove_proc')
        cfi_globals.cm.rm_callback('tlb_exec')
        cfi_globals.cm.rm_callback('control_flow_check')

# Memory page 'vaddr' became available
tlb_exec_timer = Timer()
tlb_exec_counter = 0
def tlb_exec(cpu, vaddr):
    global tlb_exec_counter
    tlb_exec_timer.start()
    tlb_exec_counter += 1
    try:
        disassembler.cache_page_if_new(vaddr)

        offsets_ptr = disassembler.waiting_for_page_ptr.get(vaddr, None)
        if offsets_ptr:
            disassembler.waiting_for_page_ptr.pop(vaddr)
            try:
                tlb_exec_timer.stop()
                for offset in offsets_ptr:
                    disassembler.disassemble_from_ptr(offset)
            finally:
                tlb_exec_timer.start()

            if cfi_globals.DEBUG_OUTPUT:
                pyrebox_print('Disassembled waiting page with pointers %.8x' % vaddr)

        offsets = disassembler.waiting_for_page.get(vaddr, None)
        if offsets:
            disassembler.waiting_for_page.pop(vaddr)
            try:
                tlb_exec_timer.stop()
                for offset in offsets:
                    disassembler.disassemble(offset)
            finally:
                tlb_exec_timer.start()

            if cfi_globals.DEBUG_OUTPUT:
                pyrebox_print('Disassembled waiting page with code %.8x' % vaddr)

    finally:
        tlb_exec_timer.stop()

# Usage of delayed check should be extremly rare
# If the current thread / process is not interrupted / preempted, will be called only once
def delayed_control_flow_check(cpu_index, cpu, tb, cur_pc, next_pc, cpu_2, vaddr):
    if cpu_2.CR3 == cfi_globals.monitored_pgd and (next_pc & PAGE_MASK) == vaddr:
        cfi_globals.cm.rm_callback('tlb_exec_' + hex(next_pc))

        # Control flow target can become valid after analysis
        if next_pc not in disassembler.bb_start_offsets:
            control_flow_check(cpu_index, cpu, tb, cur_pc, next_pc)

# Handle invalid control flow
cfi_error_cnt = 0
cfi_errors = set()
spsys = None
def control_flow_check(cpu_index, cpu, tb, cur_pc, next_pc):
    next_pc = cpu.PC

    # Majority of 'control flow is ok' conditions are handled in trigger_cfi_block_end.cpp

    # Just ignore spsys.sys driver... obfuscated by Microsoft
    if cfi_globals.MONITOR_KERNEL and next_pc >= spsys[0] and next_pc < spsys[1]:
        return

    # Target page is not yet loaded, this could be FP, delay check
    if disassembler.read(next_pc, 1) == None:
        cfi_globals.cm.add_callback(CallbackManager.TLB_EXEC_CB, functools.partial(delayed_control_flow_check, cpu_index, cpu, tb, cur_pc, next_pc), name = 'tlb_exec_' + hex(next_pc))
        if cfi_globals.DEBUG_OUTPUT:
            pyrebox_print('Used delayed check for %s -> %s' % (pp_addr(cur_pc), pp_addr(next_pc)))
        return

    # Don't handle same error multiple times
    #if next_pc in cfi_errors:
        #return

    global cfi_error_cnt
    cfi_error_cnt += 1
    cfi_errors.add(next_pc)

    '''kpcr = disassembler.kpcr()
    current_thread = kpcr.ProcessorBlock.CurrentThread.dereference_as('_ETHREAD')
    current_image = current_thread.owning_process().ImageFileName
    current_pid = current_thread.Cid.UniqueProcess'''

    # Print log about control flow error
    pyrebox_print('%s -> %s' % (pp_addr(cur_pc), pp_addr(next_pc)))
    pyrebox_print('  %s -> %s' % (instr_at(cur_pc), instr_at(next_pc)))

    if cfi_globals.ERROR_STRATEGY == 'log':
        # Whatever, print logs for all strategies
        pass
    elif cfi_globals.ERROR_STRATEGY == 'shell':
        start_shell()
    elif cfi_globals.ERROR_STRATEGY == 'dump':
        api.dump_guest_memory(cfi_globals.GUEST_DUMP_PATH)
        pyrebox_print('Dump created, changing error handling strategy to log')
        cfi_globals.ERROR_STRATEGY = 'log'

def disasm(proc_name, cpu_index, cpu):
    '''import cProfile, pstats, StringIO
    pr = cProfile.Profile()
    pr.enable()'''
    _disasm(proc_name, cpu_index, cpu)
    '''pr.disable()
    s = StringIO.StringIO()
    ps = pstats.Stats(pr, stream = s).sort_stats('cumulative')
    ps.print_stats()
    pyrebox_print(s.getvalue())'''

def _disasm(proc_name, cpu_index, cpu):
    global disassembler

    if cfi_globals.ep_bp:
        cfi_globals.ep_bp.disable()

    cfi_util.modules = get_module_list()

    pyrebox_print('-------- Initial disassembly started ---------')
    disassembler = Disassembler(proc_name, cfi_globals.monitored_pgd)
    cfi_globals.disassembler = disassembler

    copy_modules_file = open('copy_' + proc_name + '_mods.bat', 'w')
    for mod in get_module_list_ex():
        pyrebox_print('Found module: %s' % mod.get_fullname())
        pyrebox_print('  Base: %.8x Size: %.8x' % (mod.get_base(), mod.get_size()))

        # Ignore spsys.sys, possibly obfuscated, not worth the effort
        if mod.get_name() == 'spsys.sys':
            global spsys
            spsys = (mod.get_base(), mod.get_base() + mod.get_size())
            pyrebox_print('  --> Skipped!')
        else:
            copy_modules_file.write('copy "' + mod.get_fullname().replace('\SystemRoot', '%SystemRoot%') + '" .\n')
            disassembler.disassemble_module(mod.get_base(), mod.get_name())

    copy_modules_file.close()

    # Explore from IDT
    # For some reason, some IDT pointers point outside of ntoskrnl.exe to something that looks like _KiInterruptTemplate
    # Modified code from volatility/plugins/malware/idt.py
    if cfi_globals.MONITOR_KERNEL:
        pyrebox_print('Processing IDT')

        # Get the GDT for access to selector bases
        gdt = dict((i * 8, sd) for i, sd in disassembler.kpcr().gdt_entries())
        for i, entry in disassembler.kpcr().idt_entries():
            # Where the IDT entry points.
            addr = entry.Address
            # Per MITRE, add the GDT selector  base if available.
            # This allows us to detect sneaky attempts to hook IDT
            # entries by changing the entry's GDT selector.
            gdt_entry = gdt.get(entry.Selector.v())
            if gdt_entry != None and "Code" in gdt_entry.Type:
                addr += gdt_entry.Base

            disassembler.disassemble(addr)

    disassembler.print_stats()
    pyrebox_print('-------- Initial disassembly finished --------')

    # Register control flow check callback
    cfi_globals.cm.add_callback(CallbackManager.BLOCK_END_CB, control_flow_check, pgd = cfi_globals.monitored_pgd, name = 'control_flow_check')
    cfi_globals.cm.add_trigger('control_flow_check', 'triggers/trigger_cfi_block_end.so')

    # Register page swap callback
    cfi_globals.cm.add_callback(CallbackManager.TLB_EXEC_CB, tlb_exec, name = 'tlb_exec')
    if cfi_globals.MONITOR_KERNEL:
        cfi_globals.cm.add_trigger('tlb_exec', 'triggers/trigger_cfi_tlb_exec_kernel.so')
    else:
        cfi_globals.cm.add_trigger('tlb_exec', 'triggers/trigger_cfi_tlb_exec_user.so')
    cfi_globals.cm.set_trigger_var('tlb_exec', 'cr3', cfi_globals.monitored_pgd)

    cfi_globals.cm.add_callback(CallbackManager.REMOVEPROC_CB, remove_proc, name = 'remove_proc')

class Disassembler:
    MAX_INSTR_SIZE = 15
    PTR_SIZE = 4
    ADDR_SPACE_MASK = 0xFFFFFFFF

    def __init__(self, proc_name, pgd):
        self.proc_name = proc_name
        self.pgd = pgd
        self.disasm_queue = deque()
        self.processed_offsets = {0}
        self.bb_start_offsets = set()
        self.waiting_for_page_ptr = defaultdict(set)
        self.waiting_for_page = defaultdict(set)
        self.memory = {}
        self.task_space = get_addr_space(cfi_globals.monitored_pgd)

        self.disassemble_timer = Timer()

        # Get kdbg from PyREBox, saves few seconds of memory scan on every initialization
        import windows_vmi
        self.kdbg = obj.Object('_KDDEBUGGER_DATA64', offset = windows_vmi.last_kdbg, vm = self.task_space)
        #self.kdbg = tasks.get_kdbg(self.task_space)
        self._kpcr = list(self.kdbg.kpcrs())[0]

        # Update trigger configuration
        trigger_handle = CDLL('triggers/trigger_cfi_block_end-i386-softmmu.so')
        trigger_handle.reset()
        trigger_handle.set_cr3(cfi_globals.monitored_pgd)
        trigger_handle.set_monitor_kernel(cfi_globals.MONITOR_KERNEL)
        # This offset is specific to kernel version...
        trigger_handle.set_kernel_iret_addr(self.kdbg.KernBase + 0x3633A)

        self.add_bb_start_offset = trigger_handle.add_bb_start_offset
        self.get_stat = trigger_handle.get_stat

    def kpcr(self):
        return self._kpcr

    def print_stats(self):
        pyrebox_print('Disassembler processed offsets: %d' % len(self.processed_offsets))
        pyrebox_print('Basic block start offsets: %d' % len(self.bb_start_offsets))
        pyrebox_print('Pages waiting for disassembly: %d' % len(self.waiting_for_page))
        pyrebox_print('Pages with pointers waiting for disassembly: %d' % len(self.waiting_for_page_ptr))
        pyrebox_print('Time spent disassembling: %ss ' % self.disassemble_timer)

    def target_from_op(self, op):
        if op.operands[0].type == 'AbsoluteMemoryAddress':
            # [ADDR]
            return self.read_ptr(op.operands[0].disp & Disassembler.ADDR_SPACE_MASK)
        elif op.operands[0].type == 'Immediate':
            # ADDR
            return op.operands[0].value
        elif op.operands[0].type == 'Register' or op.operands[0].type == 'AbsoluteMemory':
            # REG, [REG + 0x...]
            return 0

        assert False and 'target_from_op error'

    def cache_page_if_new(self, vaddr):
        if self.memory.get(vaddr) == None:
            # api.r_va can't throw exception here if called correctly, don't even try to recover if it does
            self.memory[vaddr] = api.r_va(self.pgd, vaddr, PAGE_SIZE)

    # Read whole aligned page into cache
    # On fail, cache value as None, will be refreshed by tlb_exec
    def read_page(self, offset):
        ##assert offset & ~PAGE_MASK == 0

        res = self.memory.get(offset & PAGE_MASK, 42)
        if res == 42:
            try:
                res = api.r_va(self.pgd, offset, PAGE_SIZE)
            except RuntimeError as e:
                res = None

            self.memory[offset] = res

        return res

    # Attempts to read at least 'min_size' bytes from 'offset'
    # Can return less bytes, usually returns more bytes aligned to end of page
    def read(self, offset, min_size):
        # Lazy implementation? We don't ever need to read that much memory at once
        ##assert min_size <= 2 * PAGE_SIZE

        res = self.read_page(offset & PAGE_MASK)
        # Starting page unavailable, give up
        if not res:
            return None

        # Spans two pages
        if ((offset + min_size - 1) & PAGE_MASK) != (offset & PAGE_MASK):
            res2 = self.read_page((offset & PAGE_MASK) + PAGE_SIZE)
            if res2:
                return res[offset & ~PAGE_MASK:] + res2

        return res[offset & ~PAGE_MASK:]

    def read_ptr(self, offset):
        data = self.read(offset, Disassembler.PTR_SIZE)
        if not data or len(data) < Disassembler.PTR_SIZE:
            self.waiting_for_page_ptr[offset & PAGE_MASK].add(offset)
            return 0

        return struct.unpack('I', data[:Disassembler.PTR_SIZE])[0]

    def queue_offset(self, offset, is_bb_start = False):
        ##if offset in THROW_ON_QUEUE:
            ##raise

        if offset not in self.processed_offsets:
            ##debug_print('Queued %x' % offset)
            self.disasm_queue.append(offset)

        if is_bb_start:
            self.bb_start_offsets.add(offset)
            self.add_bb_start_offset(offset)

    def disassemble_module(self, image_base_addr, module_name):
        self.disassemble_timer.start()
        try:
            self._disassemble_module(image_base_addr, module_name)
        finally:
            self.disassemble_timer.stop()

    def _disassemble_module(self, image_base_addr, module_name):
        dos_header = obj.Object('_IMAGE_DOS_HEADER', offset = image_base_addr, vm = self.task_space)
        nt_header = dos_header.get_nt_header()

        ep_addr = image_base_addr + nt_header.OptionalHeader.AddressOfEntryPoint

        # ntdll.dll doesn't have EP, its OptionalHeader.AddressOfEntryPoint is set to 0
        if type(ep_addr) == long and ep_addr != image_base_addr:
            self._disassemble(ep_addr)

        # Use helper *.fnc file for additional basic block start offsets
        checksum = nt_header.OptionalHeader.CheckSum
        if type(checksum) != obj.NoneObject:
            helper_fname = ('scripts/fnc/' + module_name + '_' + hex(int(checksum)) + '.fnc').lower()
            ##global debug_print
            if os.path.isfile(helper_fname):
                for offset in open(helper_fname).readlines():
                    real_offset = image_base_addr + int(offset)
                    try:
                        ##if real_offset in DEBUG_ENABLE_SYMS:
                            ##debug_print = pyrebox_print
                        self._disassemble(real_offset)
                    except AssertionError:
                        import traceback
                        pyrebox_print('  Error: %s::%x %x' % (helper_fname, real_offset, int(offset)))
                        pyrebox_print(traceback.format_exc())
                    ##finally:
                        ##debug_print = print_none
            else:
                pyrebox_print('  Warning: Disassembly helper file %s not found' % helper_fname)
        else:
            pyrebox_print('  Warning: Header not found in memory, helper file disassembly skipped')

    def disassemble_from_ptr(self, offset):
        self.disassemble_timer.start()
        try:
            self._disassemble(self.read_ptr(offset))
        finally:
            self.disassemble_timer.stop()

    def disassemble(self, offset, is_bb_start = True):
        self.disassemble_timer.start()
        try:
            self._disassemble(offset, is_bb_start)
        finally:
            self.disassemble_timer.stop()

    # Internal disassemble function, start timer in wrappers
    def _disassemble(self, address, is_bb_start = True):
        ##global debug_print
        self.queue_offset(address, is_bb_start)

        while len(self.disasm_queue) > 0:
            offset = self.disasm_queue.pop()

            if offset in self.processed_offsets:
                continue

            ##if offset in DEBUG_ENABLE_SYMS:
                ##debug_print = pyrebox_print

            ##debug_print('Processing q item %x' % offset)

            # Try to read at least MAX_INSTR_SIZE bytes, most likely more
            code = self.read(offset, Disassembler.MAX_INSTR_SIZE)

            # Memory not available now
            if code == None:
                ##debug_print('Queued inaccessible page %x while disassembling %x' % (offset & PAGE_MASK, offset))
                self.waiting_for_page[offset & PAGE_MASK].add(offset)
                continue

            # Got memory, disassemble
            self.processed_offsets.add(offset)

            for op in distorm3.DecomposeGenerator(offset, code, distorm3.Decode32Bits, distorm3.DF_STOP_ON_FLOW_CONTROL):
                if not op.valid:
                    # Possibly not long enough code buffer - re-queue
                    if op.address + Disassembler.MAX_INSTR_SIZE > offset + len(code):
                        # Not even single instruction disassembled this cycle, schedule waiting for next page
                        if op.address == offset:
                            current_page = offset & PAGE_MASK
                            ##debug_print('Re-queued offset %x because of too short buffer with next page %x unaccessible ' % (offset, current_page + PAGE_SIZE))
                            ##assert (op.address + Disassembler.MAX_INSTR_SIZE) & PAGE_MASK != current_page
                            self.waiting_for_page[current_page + PAGE_SIZE].add(offset)
                            self.processed_offsets.remove(offset)
                        else:
                            ##hexdump = binascii.hexlify(code[op.address - offset:])
                            ##debug_print('Re-queued because of too short buffer at %x disassembling from %x, %d bytes left in buffer' % (op.address, offset, offset + len(code) - op.address))
                            ##debug_print('%s %s' % (hexdump, str(op)))
                            self.queue_offset(op.address)
                    else:
                        if cfi_globals.DEBUG_OUTPUT:
                            hexdump = binascii.hexlify(code[op.address - offset:][:150])
                            pyrebox_print('  Invalid code at %s disassembling from %s %d bytes left in buffer' % (pp_addr(op.address), pp_addr(offset), offset + len(code) - op.address))
                            pyrebox_print('  %s %s' % (hexdump, str(op)))
                        ##assert op.valid

                    break

                ##hexdump = binascii.hexlify(code[op.address - offset:op.address + op.size - offset])
                ##debug_print('%.8x %-32s %s' % (op.address, hexdump, str(op)))

                if op.flowControl == 'FC_NONE':
                    if 'FLAG_REP' in op.flags or 'FLAG_REPNZ' in op.flags:
                        self.queue_offset(op.address + op.size, True)
                        self.queue_offset(op.address, True)
                        continue

                    # Last instruction from buffer
                    if op.address + op.size == offset + len(code):
                        self.queue_offset(op.address + op.size)
                        break

                    continue
                # JCXZ, JO, JNO, JB, JAE, JZ, JNZ, JBE, JA, JS, JNS, JP, JNP, JL, JGE, JLE, JG, LOOP, LOOPZ, LOOPNZ
                elif op.flowControl == 'FC_CND_BRANCH':
                    self.queue_offset(self.target_from_op(op), True)
                    self.queue_offset(op.address + op.size, True)
                    break
                # JMP, JMP FAR
                elif op.flowControl == 'FC_UNC_BRANCH':
                    self.queue_offset(self.target_from_op(op), True)
                    break
                # CALL, CALL FAR
                elif op.flowControl == 'FC_CALL':
                    self.queue_offset(self.target_from_op(op), True)
                    self.queue_offset(op.address + op.size, True)
                    break
                # RET, IRET, RETF
                elif op.flowControl == 'FC_RET':
                    break
                # CMOVxx
                elif op.flowControl == 'FC_CMOV':
                    self.queue_offset(op.address + op.size)
                    break
                # INT 0x??, UD2
                elif op.flowControl == 'FC_INT':
                    # Can we track / check interrupts?
                    break
                # SYSCALL, SYSRET, SYSENTER, SYSEXIT
                elif op.flowControl == 'FC_SYS':
                    break

        ##debug_print = print_none
