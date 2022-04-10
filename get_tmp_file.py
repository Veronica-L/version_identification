import os

def get_file(binary_path):
    asmfile = 'tmp/' + binary_path + '_asm'
    comm_asm = 'objdump -d ' + binary_path + ' > ' + asmfile
    os.system(comm_asm)

    datafile = 'tmp/' + binary_path + '_data'
    comm_data = 'readelf -x .data ' + binary_path + ' > ' +datafile
    os.system(comm_data)

    rodatafile = 'tmp/' + binary_path + '_rodata'
    comm_rodata = 'readelf -x .rodata ' + binary_path + ' > ' +rodatafile
    os.system(comm_rodata)

    readelffile = 'tmp/' + binary_path + '_readelf'
    comm_rodata = 'readelf -S ' + binary_path + ' > ' +readelffile
    os.system(comm_rodata)

get_file('dnsdomainname')
        