import angr
import os
import pickle
import logging
from my_Simprocedure import BugFree
def logger_config(log_path,logging_name):
    '''
    配置log
    :param log_path: 输出log路径
    :param logging_name: 记录中name，可随意
    :return:
    '''
    '''
    logger是日志对象，handler是流处理器，console是控制台输出（没有console也可以，将不会在控制台输出，会在日志文件中输出）
    '''
    # 获取logger对象,取名
    logger = logging.getLogger(logging_name)
    # 输出DEBUG及以上级别的信息，针对所有输出的第一层过滤
    logger.setLevel(level=logging.DEBUG)
    # 获取文件日志句柄并设置日志级别，第二层过滤
    handler = logging.FileHandler(log_path, encoding='UTF-8')
    handler.setLevel(logging.INFO)
    # 生成并设置文件日志格式
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    # console相当于控制台输出，handler文件输出。获取流句柄并设置日志级别，第二层过滤
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    # 为logger对象添加句柄
    logger.addHandler(handler)
    logger.addHandler(console)
    return logger

l = logger_config(log_path='log/netstat.txt', logging_name='slice')

class Executor():
    def __init__(self, filename, project, main_func_addr, target_addrs):
        self._p = project
        self.bin_path = filename
        self._program_cfg = None
        self._function_cfg = None
        self._function_size = 0
        self._main_func_addr = main_func_addr
        self._target_addr = target_addrs
        self.avoid_list = []
        self.white_list = ['getopt_long'] + list(angr.SIM_PROCEDURES['libc'].keys())

    def find_addr_to_block(self, addr):
        for cfg_node in self._function_cfg.nodes():
            #src_addr = hex(cfg_node.addr)
            block = self._p.factory.block(cfg_node.addr)
            if addr in block.instruction_addrs:
                return block.instruction_addrs[0]
    
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


    def find_path(self, avoid_block):
        argc = 2
        argv = [self.bin_path, '-V'] 
        initial_state = self._p.factory.call_state(self._main_func_addr, argc, argv)
        simulation = self._p.factory.simgr(initial_state)

        block_addr = self.find_addr_to_block(self._target_addr)
        target_node = self._program_cfg.get_any_node(block_addr)
        irsb = self._p.factory.block(target_node.addr).vex
        statements = irsb.statements
        stmt_idx = self._target_addr - block_addr
        print(block_addr, self._target_addr, stmt_idx)

        bslice = self._p.analyses.BackwardSlice(self._program_cfg, -1, -1, targets=[(target_node, 8)], control_flow_slice=True)
        annotatedcfg = bslice.annotated_cfg()

        simulation.use_technique(angr.exploration_techniques.slicecutor.Slicecutor(annotatedcfg))
        simulation.explore(0x804d5fd)

        if simulation.found:
            solution_state = simulation.found[0]
            print(solution_state.posix.dumps(sys.stdin.fileno()))
        else:
            raise Exception('Could not find the solution')


    def _fake_function_call(self, state, function_name):
        '''将fake value填入eax'''
        new_state = state.copy()
        call_site_block = state.callstack.call_site_addr #调用当前函数基本块的地址
        call_site = state.block(addr=call_site_block).instruction_addrs[-1]
        new_state.regs.eax = new_state.solver.BVS("fake_ret_" + function_name + "_{}".format(hex(call_site)), 32)
        magic_value = 0xdeadbeef
        new_state.add_constraints(new_state.regs.eax != magic_value) 
        new_state.regs.ip = new_state.stack_pop()
        return new_state


    def if_feasible(self, path_address):
        #path_address: sequence of block addresses
        start_addr = 0x0804d4b0
        argc = 2
        argv = [self.bin_path, '-V'] 
        end_block_addr = 0x804d5dc
        start_state = self._p.factory.call_state(start_addr, argc, argv)
        candidate_states = [start_state]  # state queue to execute
        while len(candidate_states) > 0:
            state = candidate_states.pop(0)
            addr_to_step = path_address.pop(0)
            print(hex(state.addr), hex(addr_to_step))
            if state.addr != addr_to_step:
                l.error("\t[!] the address of state {} mismatch with the path, stop the execution".format(hex(state.addr)))
                break
            
            if state.addr == end_block_addr:
                l.info('[success!] find the string block!')
                break
            else:
                try:
                    succ = state.step()
                except angr.SimMemoryAddressError as e:
                    l.warning('[!] angr.SimMemoryAddressError when concrete symbolic memory address' + str(e))  # Constraint conflict occurs when address is concreted
                    break
                if len(succ.successors) > 0:
                    for sstate in succ.all_successors:
                        print('successor_state:', hex(sstate.addr), 'path_address:', hex(path_address[0]))
                        if sstate.addr == path_address[0]:
                            print('eax:', sstate.regs.eax)
                            if sstate.satisfiable():
                                candidate_states.append(sstate)
                                break
                            else:  # The selected child node constraints have conflicted
                                try:
                                    # self._collect_conflict_blocks(sstate)
                                    l.debug(
                                        "\t[*] The successor state {} is not satisfiable, early stop.".format(
                                            hex(sstate.addr)))
                                except Exception as e:
                                    l.error("[!] " + str(e.args))
                                    l.error(traceback.format_exc())

                        elif sstate.addr < self._main_func_addr or sstate.addr > self._main_func_addr + self._function_size:
                            
                            called_function_name = self.addr_to_sym_name(sstate.addr)
                            print("symbol_function", hex(sstate.addr), "function_name:", called_function_name)
                            new_state = sstate  
                            
                            if called_function_name != None:
                                '''对于不在 white_list 里的symbolic function，return fake value'''
                                if called_function_name not in self.white_list:
                                    new_state = self._fake_function_call(sstate, called_function_name)
                                    candidate_states.append(new_state)
                                else:
                                    succ = new_state.step()
                                    candidate_states += succ.successors
                            else:
                                '''对于在 avoid_list 里的函数（not symbolic function）'''
                                if sstate.addr in self.avoid_list:
                                    new_state = self._fake_function_call(sstate, called_function_name)
                                    candidate_states.append(new_state)
                                else:
                                    succ = new_state.step()
                                    candidate_states += succ.successors
                            
                        print("candidate_states:", candidate_states)

    def slice(self):
        #function_symbol = self._p.loader.find_all_symbols(self.func_name)
        #print(function_symbol)
        cfg_path = self.bin_path + ".angr_cfg"
        def cfg_gen():
            l.info("[*] Constructing CFG for {}. It may take long time.".format(self.bin_path))
            cfg = self._p.analyses.CFGFast()
            pickle.dump(cfg, open(cfg_path, 'wb'))
            return cfg
        
        if os.path.exists(cfg_path):
            try:
                cfg = pickle.load(open(cfg_path), 'rb')
            except Exception as e:
                cfg = cfg_gen()
        else:
            cfg = cfg_gen()

        self._program_cfg = cfg
        self._function_cfg = self._program_cfg.functions[self._main_func_addr].graph
        self._function_size = self._program_cfg.functions[self._main_func_addr].size
        l.info("[p] function size:{}".format(len(self._function_cfg.nodes)))


        to_slice_instr_addr = []
        slice_res_all = []
        slice_res = ['0x804d4c2', '0x804d52c', '0x804d538', '0x804d541', '0x804d546', '0x804d5fd']
        avoid_list = [0x804ffd0]
        #path_address = [0x804d4b0, 0x804d4ec, 0x804d500, 0x804d50c, 0x804d511, 0x80494a8, 0x81000a0, 0x804d538, 0x804d541, 0x804d546, 0x804d5dc]
        path_address = [134534320, 134534380, 134534400, 134534412, 134534417, 134517928, 135266464, 134534456, 134534465, 134534470, 134534620]
        self._p.hook_symbol("getopt_long", BugFree())

        self.if_feasible(path_address)

        self.find_path(avoid_block)
        for x in slice_res:
            x = int(x, 16)
            if x not in slice_res_all:
                to_slice_instr_addr.append(x)
                slice_res_all.append(x)
        
        mapped_block_set = set()
        for slice_addr in slice_res_all:
            for cfg_node in self._function_cfg.nodes():
                #src_addr = hex(cfg_node.addr)
                block = self._p.factory.block(cfg_node.addr)
                if slice_addr in block.instruction_addrs:
                    mapped_block_set.add(hex(block.instruction_addrs[0]))
        
        print(sorted(mapped_block_set))


def main():
    filename = "netstat"
    func_name = "main"
    main_func_addr = 0x804d4b0
    target_addrs = 0x804d606

    #self.path_address = [0x804d4b0, 0x8049588, 0x804d4ec, 0x80493e8, 0x804d500, 0x80496d8, 0x804d50c]

    project = angr.Project(filename, load_options={'auto_load_libs': False})
    executor = Executor(filename, project, main_func_addr, target_addrs)
    executor.slice()

if __name__=='__main__':
    main()