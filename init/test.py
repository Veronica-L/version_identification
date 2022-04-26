import angr
import argparse
import os
from my_Simprocedure import BugFree

class Binary:
    def __init__(self, file_path, version_addr):
        self.file_path = file_path
        self.version_addr = version_addr
        self._p = angr.Project(self.file_path, load_options={'auto_load_libs': False})
        self._cfg = self._p.analyses.CFGFast()
        self.main_addr = 0
        self.end_block = None
        self.func_dict = {}
        self.func_list = []

        self.white_list = ['getopt_long'] + list(angr.SIM_PROCEDURES['libc'].keys())
    
    def _get_addr_func(self, addr):
        for func_name in self.func_dict.keys():
            if addr >= self.func_dict[func_name][0] and addr<=self.func_dict[func_name][1]:
                return self.func_dict[func_name][0]
        # addr is in chunk
        os.system('/opt/idapro7.5/idat -A -c -S"get_chunk.py {}" {}'.format(addr, self.file_path))
        with open('func.txt', 'r') as f:
            lines = f.readlines()
            for line in lines:
                func_addr = line.strip('\n')
                break
            return int(func_addr)

    def _get_end_block(self):
        for node in self._cfg.nodes():
            if self.version_addr >= node.addr and self.version_addr <= node.addr+node.size:
                return node

    def addr_to_sym_name(self, addr):
        '''
        addr: function addr
        return: function name
        '''
        sym = self._p.loader.find_symbol(addr)
        if sym is not None:
            name = sym.name
        else:
            name = self._p.loader.find_plt_stub_name(addr)
        if name is not None:
            return name
        l.warning("No function name founded in addr {}".format(hex(addr)))
        return ""

    def _fake_function_call(self, state):
        '''将fake value填入eax'''
        new_state = state.copy()
        call_site_block = state.callstack.call_site_addr #调用当前函数基本块的地址
        call_site = state.block(addr=call_site_block).instruction_addrs[-1]
        new_state.regs.eax = new_state.solver.BVS("fake_ret" + "_{}".format(hex(call_site)), 32)
        magic_value = 0xdeadbeef
        new_state.add_constraints(new_state.regs.eax != magic_value) 
        new_state.regs.ip = new_state.stack_pop()
        return new_state

    def _backward_func(self, func_addr):
        while func_addr != self.main_addr:
            for node in self._cfg.nodes():
                if node.addr == func_addr:
                    func_node = node
            print(func_node.predecessors)
            pre_node = func_node.predecessors[0]
            pre_func_addr = self._get_addr_func(pre_node.addr)
            func_addr = pre_func_addr
            self.func_list.append(func_addr)
        print(self.func_list)

    
    def _step(self, start_state):
        candidate_states = [start_state]
        while len(candidate_states) > 0:
            state = candidate_states.pop(0)
            # 到达end_block
            if state.addr >= self.end_block.addr and state.addr <= self.end_block.addr+self.end_block.size:
                break
            
            # 判断跳转类型
            irsb = self._p.factory.block(state.addr).vex
            jumpkind = irsb.jumpkind
            print(jumpkind)

            try:
                succ = state.step()
            except angr.SimMemoryAddressError as e:
                l.warning('[!] angr.SimMemoryAddressError when concrete symbolic memory address' + str(e))  # Constraint conflict occurs when address is concreted
                break

            if len(succ.successors) > 0:
                print('succ.all_successors:', succ.successors)
                for succ_state in succ.successors:
                    # 必须进入的函数
                    if succ_state.addr in self.func_list:
                        candidate_states.append(succ_state)
                        continue

                    if jumpkind == 'Ijk_Call':
                        # 是否是plt
                        called_function_name = self.addr_to_sym_name(succ_state.addr)
                        print("symbol_function", hex(succ_state.addr), "function_name:", called_function_name)
                        if called_function_name != None:
                            '''对于不在 white_list 里的symbolic function，return fake value'''
                            if called_function_name not in self.white_list:
                                succ_state = self._fake_function_call(succ_state)
                                candidate_states.append(succ_state)
                            else:
                                candidate_states.append(succ_state)
                        else:
                            esp_addr = succ_state.regs.esp
                            #b'w\xda\x04\x08\xfa\xff\xfe\x7f'
                            esp_mem_bytes = succ_state.solver.eval(succ_state.memory.load(esp_addr,32),cast_to=bytes)
                            if esp_mem_bytes[4:8] != b'\x00\x00\x00\x00':
                                #'0x7ffefffa'
                                arg_mem_address = int.from_bytes(esp_mem_bytes[4:8],byteorder='little')
                                arg_mem = succ_state.solver.eval(succ_state.memory.load(arg_mem_address,32),cast_to=bytes) #b'../xz\x00-V'
                            else:
                                arg_mem = b'\x00\x00\x00\x00'
                            print("arg_mem:", arg_mem)

                            if '-h' in arg_mem.decode("utf-8"):
                                candidate_states.append(succ_state)
                            else:
                                succ_state = self._fake_function_call(succ_state)
                                candidate_states.append(succ_state)
                        

                    elif jumpkind == 'Ijk_Boring':
                        candidate_states.append(succ_state)

                    elif jumpkind == 'Ijk_Ret':
                        candidate_states.append(succ_state)
                    print(candidate_states)

    
    def _execute(self):
        argc = 2
        argv = [self.file_path, '--help'] 
        start_state = self._p.factory.call_state(self.main_addr, argc, argv)
        self._step(start_state)
        

    def run(self):
        self.main_addr = self.func_dict['main'][0]
        back_func_start = self._get_addr_func(self.version_addr)
        self.end_block = self._get_end_block()
        self._p.hook_symbol("getopt_long", BugFree())

        self.func_list.append(back_func_start)        
        self._backward_func(back_func_start)
        self._execute()
        



if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("bin", help="binary file path, such as /bin/busybox")
    args = ap.parse_args()
    file_path = args.bin

    #version_addr = 0x804f46e #xz
    #version_addr = 0x807d8aa #tar
    #version_addr = 0x8048bb5 #lnstat
    #version_addr = 0x80495cc #jq
    #version_addr = 0x804b198 #addr2line
    #version_addr = 0x8049c0c #ccguess
    version_addr = 0x804a390 #ccguess

    binary = Binary(file_path, version_addr)
    
    func_file = open('output.txt', 'r')
    func_lines = func_file.readlines()
    for line in func_lines:
        line_list = line.split('\t')
        func_name = line_list[2].strip('\n')
        binary.func_dict[func_name] = [int(line_list[0],16), int(line_list[1],16)]

    binary.run()
        
