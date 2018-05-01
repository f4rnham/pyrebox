import idaapi
import pefile

# Wait for auto-analysis to finish
Wait()

# hal.dll, halmacpi.dll
if idaapi.get_root_filename().lower().startswith('hal'):
    # Second instruction
    # lea     ecx, addr[ecx*4]
    instr = NextHead(LocByName('@HalpGenerateInterrupt@4'))
    addr = GetOperandValue(instr, 1)
    for i in range(0, 255):
        MakeFunction(addr + i * 4)

# _atexit callbacks
if LocByName('_atexit') != BADADDR:
    for ea in XrefsTo(LocByName('_atexit')):
        push_ea = PrevHead(ea.frm)
        if GetMnem(push_ea) == 'push' and GetOpnd(push_ea, 0).startswith('offset'):
            MakeFunction(GetOperandValue(push_ea, 0))

pe = pefile.PE(idaapi.get_root_filename(), fast_load = True)
checksum = pe.NT_HEADERS.OPTIONAL_HEADER.CheckSum

file = open((idaapi.get_root_filename() + '_' + hex(checksum) + '.fnc').lower(), 'w')
addr = NextFunction(0)
while addr != BADADDR:
    f = idaapi.FlowChart(idaapi.get_func(addr))
    for block in f:
        file.write(str(block.startEA - idaapi.get_imagebase()) + '\n')

    addr = NextFunction(addr)

file.close()
idaapi.qexit(0)
