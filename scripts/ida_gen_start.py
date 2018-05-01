import subprocess
import pefile
import os
from os import listdir
from os.path import isfile, join

def process_file(path, fname):
    pe = pefile.PE(join(path, fname), fast_load = True)
    checksum = pe.NT_HEADERS.OPTIONAL_HEADER.CheckSum

    if isfile((fname + '_' + hex(checksum) + '.fnc').lower()):
        return

    subprocess.run([join(os.environ['IDADIR'], 'idaw.exe'), '-A', '-S' + 'ida_gen.py', join(path, fname)])

for file in listdir('.'):
    file = file.lower()
    if file.endswith('.exe') or file.endswith('.dll') or file.endswith('.sys'):
        process_file('.', file)

