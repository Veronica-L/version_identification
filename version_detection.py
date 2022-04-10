from get_version_info import Data_info
from data_flow_init import Construct
from control_flow import CFG_Single
from my_Simprocedure import BugFree
from do_slicing import Test
import argparse
import angr
import sys

class Executor():
    def __init__(self, file_path, main_addr):
        self._file_path = file_path
        self._main_addr = main_addr
        self._probable_version_dict = {}
        self._target_addrs_dict = {}

        self._p = angr.Project(self._file_path, load_options={'auto_load_libs': False})
        self._cfg = self._p.analyses.CFGFast()
        self._function_cfg = self._cfg.functions[self._main_addr].graph
        #self._function_size = self._cfg.functions[self._main_addr].size
        self.white_list = ['getopt_long'] + list(angr.SIM_PROCEDURES['libc'].keys())

        self._taint_node_list = [] #污染点
        self._taint_block_list = [] #污染的block
        self._track_call = [] #需要跟踪的call
        self._not_track_call = [] #不需要跟踪的call

        self.forward_block_list = [] #从起点往后追溯block
        self.back_block_list = [] #从后往前追溯block

        self._p.hook_symbol("getopt_long", BugFree())
    
    # 获得addr对应的block
    def find_addr_to_block(self, addr):
        for cfg_node in self._cfg.nodes():
            #src_addr = hex(cfg_node.addr)
            block = self._p.factory.block(cfg_node.addr)
            if addr in block.instruction_addrs:
                return block.instruction_addrs[0]


    def _get_probable_version(self):
        data_info = Data_info(self._file_path)
        data_info.run()
        # {version:[用到version变量的addr list]}
        self._probable_version_dict = data_info.probable_version_dict
        print(self._probable_version_dict)

        for version_str in self._probable_version_dict.keys():
            for addr in self._probable_version_dict[version_str]:
                block_addr = self.find_addr_to_block(addr)
                if block_addr not in self._target_addrs_dict.keys():
                    self._target_addrs_dict[block_addr] = []
                self._target_addrs_dict[block_addr].append(version_str)

        print(self._target_addrs_dict)
    

    def _get_taint_nodes(self):
        dataflow = Construct(self._file_path, self._main_addr, self._p, self._cfg, self._function_cfg)
        self.taint_node_list = dataflow.get_data_flow()
        track_call_list = dataflow.track_call
        not_track_call_list = dataflow.not_track_call

        #self._cfg = dataflow.cfg
        #self._function_cfg = dataflow.function_cfg

        for track in track_call_list: #将<pyvex.Expr.Const> 转为 str
            track = int(str(track), 16)
            self._track_call.append(track)
        for not_track in not_track_call_list:
            not_track = int(str(not_track), 16)
            self._not_track_call.append(not_track)
        
        print(self.taint_node_list, self._track_call, self._not_track_call)


        for t_node in self.taint_node_list:
            addr_int = int(t_node[1], 16)
            block_addr = self.find_addr_to_block(addr_int)
            if block_addr not in self._taint_block_list:
                self._taint_block_list.append(self.find_addr_to_block(addr_int))
        print('taint_block_list:', self._taint_block_list)

    # 从后向前 target_block_addr:version所在的block
    # end_addr: CMP的block
    def _get_block_cfg(self, target_block_addr):
        end_addr = self._taint_block_list[-1]
        block_cfg = CFG_Single(self._file_path, self._p, self._cfg, self._function_cfg, self._main_addr, target_block_addr, end_addr)
        back_block_list = block_cfg.get_cfg()
        return back_block_list


    def _find_block(self, candidate_node, next_taint_bl_addr):
        while len(candidate_node) > 0:
            node = candidate_node.pop(0)
            if node.addr not in self.forward_block_list:
                self.forward_block_list.append(node.addr)
            if node.addr == next_taint_bl_addr:
                return self.forward_block_list

            successor_bl_nodes = node.successors
            for s_node in successor_bl_nodes:
                print(s_node)
                # 判断s_node是否是symbol
                if s_node.name and s_node.name not in self.white_list:
                    if self._p.loader.find_symbol(s_node.name):
                        s_node = self._cfg.get_any_node(self.find_addr_to_block(node.addr+node.size))
                # 判断s_node是否是不track的call
                if s_node.addr in self._not_track_call:
                    s_node = self._cfg.get_any_node(self.find_addr_to_block(node.addr+node.size))
                candidate_node.append(s_node)
                print('candidate:', candidate_node)
                try:
                    return self._find_block(candidate_node, next_taint_bl_addr)
                except Exception as e:
                    print("[!] can't find route")

    # 从前向后
    # 因为taint_block不一定是连续的，所以要得到中间的block得到一条链路
    def _get_forward_bl_list(self):
        for i, bl_addr in enumerate(self._taint_block_list):
            if i == len(self._taint_block_list)-1:
                break
            next_taint_bl_addr = self._taint_block_list[i+1]
            current_taint_bl_node = self._cfg.get_any_node(bl_addr)
            next_taint_bl_node = self._cfg.get_any_node(next_taint_bl_addr)
            candidate_node = [current_taint_bl_node]

            self._find_block(candidate_node, next_taint_bl_addr)
        
        print('forward_block_list:', self.forward_block_list)



    def version_detect(self):
        # 对于每一个可能的version string, 做一条block的切片
        for target_block_addr in self._target_addrs_dict.keys():
            print('version strings:', self._target_addrs_dict[target_block_addr])
            back_block_list = self._get_block_cfg(target_block_addr)

            # 如果block list最后一个元素（追溯结束）不等于 数据流block的最后一个元素
            if back_block_list[-1].addr != self._taint_block_list[-1]:
                continue
            
            back_block_list.reverse()
            for index, block_node in enumerate(back_block_list):
                 back_block_list[index] = block_node.addr

            slice_block_list = self.forward_block_list[:-1] + back_block_list
            print('slice_block_list:', slice_block_list)

            state_test = Test(self._file_path, self._p, self._cfg, self._function_cfg, self._main_addr, target_block_addr, slice_block_list)

            if_find = state_test.slice()
            print('[!!!] version is ', self._target_addrs_dict[target_block_addr])
            
        
        

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bin", help="binary file path, such as /bin/busybox")
    args = ap.parse_args()
    file_path = args.bin
    #main_addr = 0x804d4b0
    #main_addr = 0x80495b0 
    #main_addr = 0x8049880 #chown
    main_addr = 0x8049700  #dnsdomainname
    #main_addr = 0x804b1a0

    executor = Executor(file_path, main_addr)
    executor._get_probable_version()
    executor._get_taint_nodes()
    executor._get_forward_bl_list()
    executor.version_detect()


if __name__=='__main__':
    main()