import angr
import os
import pickle

class CFG_Single():
    def __init__(self, filename, project, program_cfg, function_cfg, main_func_addr, target_addr, end_addr):
        self._p = project
        self.bin_path = filename
        self._program_cfg = program_cfg
        self._function_cfg = function_cfg
        self._function_size = 0
        self._main_func_addr = main_func_addr
        self._target_addr = target_addr
        self._end_addr = end_addr
        self._back_from_node = None
        self._back_end_node = None
        
        self.avoid_list = []
        self.white_list = ['getopt_long'] + list(angr.SIM_PROCEDURES['libc'].keys())
        self.back_block_list = []

    # 获得addr对应的block
    def find_addr_to_block(self, addr):
        for cfg_node in self._program_cfg.nodes():
            #src_addr = hex(cfg_node.addr)
            block = self._p.factory.block(cfg_node.addr)
            if addr in block.instruction_addrs:
                return block.instruction_addrs[0]


    def find_backward_block(self, candidate_node):
        while len(candidate_node) > 0:
            node = candidate_node.pop(0)
            self.back_block_list.append(node)
            if node.addr == self._end_addr:
                return self.back_block_list
            pre_nodes = node.predecessors

            for pre_n in pre_nodes:
                 # 判断pre_nodes是否是symbol
                if pre_n.name:
                    if self._p.loader.find_symbol(pre_n.name):
                        pre_n = self._program_cfg.get_any_node(self.find_addr_to_block(node.addr-5))
                candidate_node.append(pre_n)
                try:
                    return self.find_backward_block(candidate_node)
                except Exception as e:
                    print("[!] can't find route")
        


    def get_cfg(self):
        #function_symbol = self._p.loader.find_all_symbols(self.func_name)
        #print(function_symbol)
        '''
        cfg_path = self.bin_path + ".angr_cfg"
        def cfg_gen():
            #l.info("[*] Constructing CFG for {}. It may take long time.".format(self.bin_path))
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
        '''

        self._function_cfg = self._program_cfg.functions[self._main_func_addr]
        self._function_size = self._program_cfg.functions[self._main_func_addr].size
        #l.info("[p] function size:{}".format(self._function_size))

        self._back_from_node = self._program_cfg.get_any_node(self._target_addr) #target node block
        self._back_end_node = self._program_cfg.get_any_node(self._end_addr)
        candidate_node = [self._back_from_node]
        
        self.find_backward_block(candidate_node)

        print('back_block_list:',self.back_block_list)
        
        return self.back_block_list

        

'''
def main():
    filename = "netstat"
    func_name = "main"
    main_func_addr = 0x804d4b0
    target_addrs = 0x804d606

    #self.path_address = [0x804d4b0, 0x8049588, 0x804d4ec, 0x80493e8, 0x804d500, 0x80496d8, 0x804d50c]

    project = angr.Project(filename, load_options={'auto_load_libs': False})
    executor = CFG_Single(filename, project, main_func_addr, target_addrs)
    executor.get_cfg()

if __name__=='__main__':
    main()
'''