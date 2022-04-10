import subprocess
import argparse
import angr
import os

class Info(object):
    def __init__(self):
        self.args = None
        self.picflag = None
        self.project = None #angr.project
        self.binaryfile = None
        self.asmfile = None
        self.hexdumpfile = None
        self.readelffile = None

        # a list of [section_name, section_type, section_address, section_offset, section_size]
        self.sectionsinfo = []

        # a dict from section_name to [section_name, section_type, section_address, section_offset, section_size]
        self.sectionsinfo_name_map = {}

        self.mmin_data_section_addr = None
        self.mmax_data_section_addr = None

        # data section names
        self.data_section_names = [".rodata", ".niprod", ".nipd", ".bss", ".tbss", ".data.rel.ro", ".data"]

        # list of instruction addresses
        self.insnaddrs = []
        # instruction address to objdump insn string line map
        self.insnlinesmap = {}
        # instruction address to objdump insn string line (excluding address and bytes) map
        self.insnstringsmap = {}


        # func addr to a list of ret instruction addresses
        self.ret_insn_addresses = []
        self.func_ret_insn_addresses_map = {}
        self.jmp_insn_addresses = []
        self.func_jmp_insn_addresses_map = {}
        self.call_insn_addresses = []
        self.func_call_insn_addresses_map = {}

        self.callsite_explicit_call_targets_map = {}
        self.cond_uncond_jump_insn_oprands = ["jmp", "js", "jnp", "jge", "jbe", "jb", "jns", "jp", "jl", "ja", "jle", "jne", "jg", "je", "jae"]
        self.cond_uncond_jump_insn_addresses = []
        self.func_cond_uncond_jump_insn_addresses_map = {}

        self.uncond_jump_insn_oprands = ["jmp"]
        self.uncond_jump_insn_addresses = []
        self.func_uncond_jump_insn_addresses_map = {}
        
        self.cond_jump_insn_oprands = ["js", "jnp", "jge", "jbe", "jb", "jns", "jp", "jl", "ja", "jle", "jne", "jg", "je", "jae"]
        self.cond_jump_insn_addresses = []
        self.func_cond_jump_insn_addresses_map = {}

        self.func_explicit_non_fall_through_control_flow_targets_map = {}

global info
info = Info()

def parse_parameters():
    parser = argparse.ArgumentParser(description='SelectiveTaint static analysis')
    parser.add_argument("-input", help = "input enclave binary file", type=str, required=True)
    info.args = parser.parse_args()

def load_binary():
    file_command_return_string = subprocess.check_output(['file', info.args.input]).decode('utf-8')

    if "shared object" in file_command_return_string and "dynamically linked" in file_command_return_string:
        info.picflag = 1
    else:
        info.picflag = 0
    
    try:
        info.project = angr.Project(info.args.input,load_options={'auto_load_libs': False})
    except:
        info.picflag = 0
        info.project = angr.Project(info.args.input,main_opts = {'backend': 'blob'},load_options={'auto_load_libs': False})

    print(file_command_return_string)

def disassemble():
    info.binaryfile = os.path.realpath(info.args.input)
    # generate objdump file
    # display assembler contents of executable sections
    tmpfile = "./tmp/" + os.path.basename(info.binaryfile) + "_asm"
    info.asmfile = tmpfile
    comm = "objdump -d " + info.binaryfile + " > " + tmpfile
    os.system(comm)

    # generate hexdump file
    # Displays chars in hexl and ASCII
    tmpfile = "./tmp/" + os.path.basename(info.binaryfile) + "_hexdump"
    info.hexdumpfile = tmpfile
    comm = "hexdump -C " + info.binaryfile + " > " + tmpfile
    os.system(comm)

    # generate readelf section info file
    # display section headers
    tmpfile = "./tmp/" + os.path.basename(info.binaryfile) + "_readelf"
    info.readelffile = tmpfile
    comm = "readelf -S " + info.binaryfile + " > " + tmpfile
    os.system(comm)

def readelf_sections_info():
    f = open(info.readelffile,'r')
    lines = f.readlines()
    for line in lines:
        if "[" in line and "]" in line:
            s = line[line.index("[")+1:line.index("]")].strip()
            if s.isnumeric():
                restline = line[line.index("]")+1:].strip().split()
                if int(s, 10) != 0:
                    info.sectionsinfo.append([restline[0], restline[1], int(restline[2], 16), int(restline[3], 16), int(restline[4], 16)])
                    info.sectionsinfo_name_map[restline[0]] = [restline[0], restline[1], int(restline[2], 16), int(restline[3], 16), int(restline[4], 16)]
    f.close()
    print(info.sectionsinfo_name_map)

    info.mmin_data_section_addr = 0xffffffffffffffff
    info.mmax_data_section_addr = -0x1

    for sectioninfo_name in sorted(info.sectionsinfo_name_map):
        if info.sectionsinfo_name_map[sectioninfo_name][0] in info.data_section_names:
            start = info.sectionsinfo_name_map[sectioninfo_name][2]
            end = info.sectionsinfo_name_map[sectioninfo_name][2] + info.sectionsinfo_name_map[sectioninfo_name][4] - 0x1

            if start < info.mmin_data_section_addr:
                info.mmin_data_section_addr = start
            if end > info.mmax_data_section_addr:
                info.mmax_data_section_addr = end

def find_ins_addr():
    f = open(info.asmfile, 'r')
    lines = f.readlines()
    for line in lines:
        if len(line.strip().split()) != 0:
            l = line.strip().split()[0] 
            
            if "<" in line and ">:" in line:
                func_addr = int(line[:line.index("<")], 16)
                print(func_addr)

            if ":" in l and len(l) >= 2:
                addr = -1
                ll = l[:-1]
                try:
                    addr = int(ll, 16)
                except:
                    continue
                
                info.insnaddrs.append(addr)
                info.insnlinesmap[addr] = line
                s = line.strip().split("\t")

                if len(s) >= 3:
                    info.insnstringsmap[addr] = s[-1]
                else:
                    info.insnstringsmap[addr] = ""
                    continue

                s = info.insnstringsmap[addr].strip().split()[0]

                print(info.insnstringsmap)
                # ret
                if info.insnstringsmap[addr].startswith("ret") or info.insnstringsmap[addr].startswith("repz ret"):
                    info.ret_insn_addresses.append(addr)
                    if func_addr not in info.func_ret_insn_addresses_map:
                        info.func_ret_insn_addresses_map[func_addr] = []
                    info.func_ret_insn_addresses_map[func_addr].append(addr)
                # jmp
                if info.insnstringsmap[addr].startswith("jmp"):
                    info.jmp_insn_addresses.append(addr)
                    if func_addr not in info.func_jmp_insn_addresses_map:
                        info.func_jmp_insn_addresses_map[func_addr] = []
                    info.func_jmp_insn_addresses_map[func_addr].append(addr)
                # call
                if info.insnstringsmap[addr].startswith("call"):
                    info.call_insn_addresses.append(addr)
                    if func_addr not in info.func_call_insn_addresses_map:
                        info.func_call_insn_addresses_map[func_addr] = []
                    info.func_call_insn_addresses_map[func_addr].append(addr)
                    s1 = info.insnstringsmap[addr].strip().split()[1]
                    target_addr = -1
                    try:
                        target_addr = int(s1, 16)
                    except:
                        continue
                    info.callsite_explicit_call_targets_map[addr] = target_addr

                if s in info.cond_uncond_jump_insn_oprands:
                    info.cond_uncond_jump_insn_addresses.append(addr)
                    if func_addr not in info.func_cond_uncond_jump_insn_addresses_map:
                        info.func_cond_uncond_jump_insn_addresses_map[func_addr] = []
                    info.func_cond_uncond_jump_insn_addresses_map[func_addr].append(addr)
                    if s in info.uncond_jump_insn_oprands:
                        info.uncond_jump_insn_addresses.append(addr)
                        if func_addr not in info.func_uncond_jump_insn_addresses_map:
                            info.func_uncond_jump_insn_addresses_map[func_addr] = []
                        info.func_uncond_jump_insn_addresses_map[func_addr].append(addr)
                    if s in info.cond_jump_insn_oprands:
                        info.cond_jump_insn_addresses.append(addr)
                        if func_addr not in info.func_cond_jump_insn_addresses_map:
                            info.func_cond_jump_insn_addresses_map[func_addr] = []
                        info.func_cond_jump_insn_addresses_map[func_addr].append(addr)
                    
                    s1 = info.insnstringsmap[addr].strip().split()[1]
                    target_addr = -1
                    try:
                        target_addr = int(s1, 16)
                    except:
                        continue
                    
                    if func_addr not in info.func_explicit_non_fall_through_control_flow_targets_map:
                        info.func_explicit_non_fall_through_control_flow_targets_map[func_addr] = set()
                    info.func_explicit_non_fall_through_control_flow_targets_map[func_addr] = info.func_explicit_non_fall_through_control_flow_targets_map[func_addr].union(set([target_addr]))

    f.close()
    print(info.insnaddrs, info.insnlinesmap)




def main():
    parse_parameters()
    load_binary()
    disassemble()
    readelf_sections_info()
    find_ins_addr()

if __name__ == "__main__":
	main()
