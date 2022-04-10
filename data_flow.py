import angr
import pyvex
import os
import miasm_v.core.graph as graph

#有加减乘除操作的节点
class Op_node():
    def __init__(self, reg_name, const_int, opration):
        self.reg_name = reg_name
        self.const_int = const_int
        self.opration = opration

#内存节点[eax]/[eax+0x4]
class Mem_node():
    def __init__(self, mem):
        self.mem = mem

# graph节点
class Node():
    def __init__(self, node_name, addr, read_or_write):
        self.node_name = node_name
        self.addr = addr
        self.read_or_write = read_or_write

class Construct():
    def __init__(self, filename, func_addr, project, cfg, function_cfg):
        self.filename = filename
        self.func_addr = func_addr
        self.p = project
        self.arch = self.p.arch
        self.cfg = cfg
        self.function_cfg = function_cfg
        self.is_taint = {}

        self.tmp_variable = {}
        self.reg_variable = {}
        self.flow_graph = graph.DiGraph()
        self.exists_nodes = {}
        self.mem_store = {}
        self.taint_list = []
        self.track_call = [] # 需要跟踪的call
        self.not_track_call = []

        self.taint_eax = False
        self.eax_node = None
        self.taint_variable_list = []

        self.end_flag = False

    
    def _need_to_ignore(self, stmt, stmt_idx):
        if stmt.tag == 'Ist_IMark':
            return True
    
    #创建节点
    def create_node(self, node_name, addr, read_or_write):
        node = (node_name, hex(addr), read_or_write)
        return node

    def get_keys(self, d, value):
        return [k for k,v in d.items() if v == value]

    def exists_mem(self, mem_node):
        is_Op = False
        if isinstance(mem_node.mem, Op_node):
            is_Op = True

        for key in self.exists_nodes.keys():
            if isinstance(key, Mem_node):
                if isinstance(key.mem, Op_node): #[esp+0x4]这种类型
                    reg_name = key.mem.reg_name
                    const_int = key.mem.const_int
                    opration = key.mem.opration
                    if is_Op == True:
                        if mem_node.mem.reg_name == reg_name and mem_node.mem.const_int == const_int and mem_node.mem.opration == opration:
                            return key
                else:
                    reg_name = key.mem
                    if is_Op == False:
                        if mem_node.mem == reg_name:
                            return key
        return mem_node

    #分析block里的statement
    def get_expression(self, statements):
        for stmt_idx, stmt in enumerate(statements):#遍历每条语句
            if stmt.tag == 'Ist_IMark':
                stmt_addr = stmt.addr

                #print(self.exists_nodes) 
                #print(self.tmp_variable) 
                #print(self.flow_graph)

                #每一条语句结束后，tmp如果对应的是op_node, 改为对应寄存器
                for tmp in self.tmp_variable.keys():
                    if isinstance(self.tmp_variable[tmp], Op_node):
                        self.tmp_variable[tmp] = self.tmp_variable[tmp].reg_name
                
            if self._need_to_ignore(stmt, stmt_idx):
                continue

            #print(stmt.addr, stmt.data, stmt.end) #stmt.data存到stmt.addr
            if isinstance(stmt, pyvex.IRStmt.WrTmp):
                data_to_tmp = stmt.tmp
                data_get_from = stmt.data 
                #print(stmt.tmp, type(stmt.data), stmt.data)

                if isinstance(data_get_from, pyvex.expr.Get):
                    #GET:I32(esp) 寄存器类型 #offset
                    reg_name = self.p.arch.register_names[data_get_from.offset]
                    self.tmp_variable[str(data_to_tmp)] = reg_name

                    if self.taint_eax == True and reg_name == 'eax':
                        # 将eax加入taint node
                        self.eax_node = self.create_node('eax', stmt_addr, 'w')
                        self.flow_graph.add_node(self.eax_node)
                        self.taint_variable_list.append(str(data_to_tmp))
                        self.taint_eax = False

                if isinstance(data_get_from, pyvex.expr.RdTmp):
                    # t8 = t10
                    rdtmp = data_get_from
                    self.tmp_variable[str(data_to_tmp)] = self.tmp_variable[str(rdtmp.tmp)]

                    # 污点tmp
                    if str(rdtmp.tmp) in self.taint_variable_list:
                        self.taint_variable_list.append(str(data_to_tmp))                    
                    

                elif isinstance(data_get_from, pyvex.expr.Binop):
                    # Sub32(t30,0x00000004) And32(t29,0xfffffff0)
                    #print(data_get_from.op_int, data_get_from.args, data_get_from.op, data_get_from.child_expressions)

                    if isinstance(data_get_from.args[0], pyvex.expr.RdTmp) and isinstance(data_get_from.args[1], pyvex.expr.Const):
                        rdtmp = data_get_from.args[0] #t30
                        const_int = data_get_from.args[1] #0x00000004 pyvex.expr.Const

                        if str(rdtmp.tmp) in self.tmp_variable.keys(): 
                            #tmp有对应的寄存器名称
                            from_reg_name = self.tmp_variable[str(rdtmp.tmp)] #t30对应的寄存器名称
                        elif str(rdtmp.tmp) in self.reg_variable.values(): 
                            #tmp没有对应的寄存器，但是它的值和某个reg一样
                            reg_list = self.get_keys(self.reg_variable, str(rdtmp.tmp))
                            from_reg_name = reg_list[0]
                            self.tmp_variable[str(rdtmp.tmp)] = reg_list[0]

                        int_value = const_int.con.value #0x00000004
                        op_node = Op_node(from_reg_name, int_value, data_get_from.op)
                        self.tmp_variable[str(data_to_tmp)] = op_node
                            
                        # 污点tmp
                        if str(rdtmp.tmp) in self.taint_variable_list:
                            self.taint_variable_list.append(str(data_to_tmp))


                elif isinstance(data_get_from, pyvex.expr.Load):
                    #t40 = LDle:I32(t38)
                    #print(type(data_get_from.addr))
                    if isinstance(data_get_from.addr, pyvex.expr.RdTmp): #右边是tmp 读的tmp对应的内存
                        rdtmp = data_get_from.addr
                        if rdtmp.tmp == 51 and self.tmp_variable[str(rdtmp.tmp)] == 'gs':
                            self.tmp_variable[str(data_to_tmp)] = 'eax'
                            continue
                        self.tmp_variable[str(data_to_tmp)] = Mem_node(self.tmp_variable[str(rdtmp.tmp)])

                elif isinstance(data_get_from, pyvex.expr.Unop):
                    if isinstance(data_get_from.args[0], pyvex.expr.RdTmp):
                        # t46 = 16Uto32(t47)
                        rdtmp = data_get_from.args[0]
                        self.tmp_variable[str(data_to_tmp)] = self.tmp_variable[str(rdtmp.tmp)]
                        
                        # 污点tmp
                        if str(rdtmp.tmp) in self.taint_variable_list:
                            self.taint_variable_list.append(str(data_to_tmp))
                
                elif isinstance(data_get_from, pyvex.expr.CCall):
                    args = data_get_from.args
                    for a in args:
                        if isinstance(a, pyvex.expr.RdTmp):
                            rdtmp = a
                            if self.tmp_variable[str(rdtmp.tmp)] == 'gs':
                                self.tmp_variable[str(data_to_tmp)] = 'gs'
                                write_node = self.create_node('eax', stmt_addr, 'w')
                                read_node = self.create_node('gs', stmt_addr, 'r')
                                self.flow_graph.add_uniq_edge(read_node, write_node)
                    
                        
            elif isinstance(stmt, pyvex.stmt.Put):
                # PUT(esp) = t29
                data_to_reg = stmt.offset #register:offset
                data_get_from = stmt.data
                #print(data_to_reg, data_get_from)

                reg_name = self.p.arch.register_names[data_to_reg] #? 左边是否一定是寄存器

                if reg_name == 'eip' or reg_name.startswith('cc_'):
                    continue
                if isinstance(data_get_from, pyvex.expr.RdTmp): #右边是tmp
                    tmp_value = self.tmp_variable[str(data_get_from.tmp)]
                    
                    if isinstance(tmp_value, Op_node): 
                        #t29 = Sub32(t30,0x00000004), 我们只想要t30 -> t29
                        tmp_value = tmp_value.reg_name

                    if tmp_value not in self.exists_nodes: #如果节点不在exist_nodes里面
                        read_node = self.create_node(tmp_value, stmt_addr, 'r')
                        self.exists_nodes[tmp_value] = read_node
                    else:
                        read_node = self.exists_nodes[tmp_value]
                    write_node = self.create_node(reg_name, stmt_addr, 'w')
                    self.exists_nodes[reg_name] = write_node
                    self.flow_graph.add_uniq_edge(read_node, write_node)
                    
                    # 寄存器对应的tmp
                    self.reg_variable[reg_name] = str(data_get_from.tmp) #ebp:tmp
                    # 删除之前对应是reg_name的tmp，避免混淆
                    if reg_name in self.tmp_variable.values():
                        keys_list = self.get_keys(self.tmp_variable, reg_name)
                        for k in keys_list:
                            del self.tmp_variable[k]

                if isinstance(data_get_from, pyvex.expr.Const): #右边是Const
                    const_int = data_get_from
                    write_node = self.create_node(reg_name, stmt_addr, 'w')
                    self.exists_nodes[reg_name] = write_node

                if reg_name == tmp_value:
                    self.tmp_variable[str(data_get_from.tmp)] = tmp_value
                
                # todo!
                #else: #右边是int

            elif isinstance(stmt, pyvex.stmt.Store):
                # STle(t29) = t0
                #print(stmt.addr, stmt.data)
                data_to = stmt.addr 
                data_get_from = stmt.data
                #write
                if isinstance(data_to, pyvex.expr.RdTmp): #左边是tmp
                    w_tmp_value = self.tmp_variable[str(data_to.tmp)]
                    mem_node = Mem_node(w_tmp_value)
                    #write_node = self.create_node(mem_node, stmt_addr, 'w')

                    # 判断mem_node是否存在于exists_nodes
                    mn = self.exists_mem(mem_node)
                    write_node = self.create_node(mn, stmt_addr, 'w')
                    self.exists_nodes[mn] = write_node

                if isinstance(data_to, pyvex.expr.Const): #左边是地址
                    mn = data_to

                #read
                if isinstance(data_get_from, pyvex.expr.RdTmp): #右边是tmp
                    r_tmp_value = self.tmp_variable[str(data_get_from.tmp)]

                    if r_tmp_value not in self.exists_nodes: #如果节点不在exist_nodes里面
                        read_node = self.create_node(r_tmp_value, stmt_addr, 'r')
                        self.exists_nodes[r_tmp_value] = read_node
                    else:
                        read_node = self.exists_nodes[r_tmp_value]
                    self.mem_store[mn] = read_node
                
                if isinstance(data_get_from, pyvex.expr.Const): #右边是Const
                    self.mem_store[mn] = data_get_from
                    continue

                self.flow_graph.add_uniq_edge(read_node, write_node)

            elif isinstance(stmt, pyvex.stmt.Exit):
                #print(type(stmt.guard), stmt.dst, stmt.offsIP, stmt.jk)
                if isinstance(stmt.guard, pyvex.expr.RdTmp):
                    rdtmp = stmt.guard
                    if str(rdtmp.tmp) in self.taint_variable_list:
                        self.end_flag = True
                        break
            #print('taint_variable_list:', self.taint_variable_list)

    # find taint node
    def analysis_taint(self): # node_and_edge:[node, edge]
        nodes = self.node_and_edge[0]
        edges = self.node_and_edge[1]

        for n_id in nodes.keys():
            n = nodes[n_id]
            node_name = n[0]
            addr = n[1]
            read_or_write = n[2]
            
            # source
            if isinstance(node_name, Mem_node):   
                if isinstance(node_name.mem, Op_node):
                    ''' just test
                    if addr == '0x804d4c2':
                        print('source', node_name, node_name.mem.reg_name, node_name.mem.const_int, node_name.mem.opration)
                        print(n)
                    '''
                    if node_name.mem.reg_name == 'ebp' and node_name.mem.const_int == 12: #and node_name.mem.opration == 'Iop_And32': #[ebp+argv]
                        if read_or_write == 'r' and addr == '0x804b2bc':
                            if n_id in self.taint_list:
                                continue
                            self.taint_list.append(n_id)
                            continue

        # eax_node 加入 taint
        if self.eax_node:
            if self.eax_node in nodes.values(): 
                n_id = self.get_keys(nodes, self.eax_node)[0]
                self.taint_list.append(n_id)

                self.eax_node = None

        # find taint node
        # edge: {to_node:{from_node1, from_node2}}
        for from_nodes in edges.values():
            for from_node in from_nodes:
                if from_node in self.taint_list:
                    keys_list = self.get_keys(edges, from_nodes)
                    for key in keys_list:
                        if key in self.taint_list:
                            continue
                        else:
                            self.taint_list.append(key)
            
    def check_esp(self, mem_node, nodes):
        node = self.mem_store[mem_node]
        #print('mem_store', self.mem_store)
        #print(mem_node, node)
        #node = self.exists_nodes[mem_node]
        node_id = self.get_keys(nodes, node)[0]
        #print('args', node_id)
        #value_set = (self.exists_nodes[mem_node].node_name, self.exists_nodes[mem_node].node_name.addr, 'r')
        #print(value_set)
        #if value_set in nodes.values():
            #keys_list = self.get_keys(nodes, value_set)

        if node_id in self.taint_list:
            return True
        return False

    #判断[esp], 进而判断是否要跟踪call
    def if_enter_call(self): 
        nodes = self.node_and_edge[0]
        edges = self.node_and_edge[1]

        for mem_node in self.mem_store.keys():
            if isinstance(self.mem_store[mem_node], pyvex.expr.Const):
                #print('const:', mem_node)
                continue
            if isinstance(mem_node.mem, Op_node): #[esp+0x4]这种类型
                #print('op_node:', mem_node.mem.reg_name, mem_node.mem.opration)
                if mem_node.mem.reg_name == 'esp' and mem_node.mem.opration == 'Iop_Add32':
                    #print(mem_node)
                    if self.check_esp(mem_node, nodes):
                        return True
            if mem_node.mem == 'esp': #[esp]这种类型
                #print('esp:', mem_node)
                if self.check_esp(mem_node, nodes):
                    return True
        return False

    # 分析完call之后清空[esp]
    '''
    def clear_stack(self):
        nodes = self.node_and_edge[0]
        
        for e_node in self.exists_nodes.keys():
            if isinstance(e_node, Mem_node):
                if isinstance(e_node.mem, Op_node): #[esp+0x4]这种类型
                    if e_node.mem.reg_name == 'esp' and e_node.mem.opration == 'Iop_And32':
                        if self.check_esp(e_node, nodes):
                            # clear
                            del self.exists_nodes[e_node]
                if e_node.mem == 'esp':
                    if self.check_esp(e_node, nodes):
                        # clear
                        del self.exists_nodes[e_node]
    '''
    def clear_stack(self):
        nodes = self.node_and_edge[0]
        '''
        for m in self.mem_store.keys():
            if isinstance(m.mem, Op_node): #[esp+0x4]这种类型
                if m.mem.reg_name == 'esp' and m.mem.opration == 'Iop_Add32':
                    del self.exists_nodes[m]
                    del self.mem_store[m]
            if m.mem == 'esp':
                del self.exists_nodes[m]
                del self.mem_store[m]
        '''
        
        for m in list(self.mem_store.keys()):
            if isinstance(m, pyvex.expr.Const):
                continue
            if isinstance(m.mem, Op_node): #[esp+0x4]这种类型
                if m.mem.reg_name == 'esp' and m.mem.opration == 'Iop_Add32':
                    self.mem_store.pop(m)
                    self.exists_nodes.pop(m)
            if m.mem == 'esp':
                self.mem_store.pop(m)
                self.exists_nodes.pop(m)

    
    def get_data_flow(self):
        #self.function_cfg = self.cfg.functions[self.func_addr].graph
        #source_node = Mem_node(Op_node('ebp', 12, Iop_Add32))
        for cfg_node in self.function_cfg.nodes():
            src_addr = cfg_node.addr
            try:
                irsb = self.p.factory.block(cfg_node.addr).vex
                
            except Exception as e:
                #l.debug(e)
                continue
            
            statements = irsb.statements
            print(irsb.next, irsb.jumpkind)
            self.get_expression(statements)

            #分析flow graph, 看哪些被污染
            self.node_and_edge = self.flow_graph.get_node_and_edge()
            #print(self.node_and_edge)
            self.analysis_taint()
            print('taint_list:\n', self.taint_list)

            if self.end_flag == True:
                #self.end_flag = False
                break

            if irsb.jumpkind == 'Ijk_Call':
                # 判断是否进入call
                # 跟踪call
                if self.if_enter_call(): 
                    self.track_call.append(irsb.next)
                    print('track_call:', irsb.next)
                    self.taint_eax = True
                    
                else:
                    self.not_track_call.append(irsb.next)
                    print('not_track_call:', irsb.next)
                #分析完对[esp]弹出
                self.clear_stack()

            #print(self.flow_graph)
            #print(self.exists_nodes)

        taint_node_list = []
        nodes = self.node_and_edge[0]
        for n_id in self.taint_list:
            taint_node = nodes[n_id]
            taint_node_list.append(taint_node)
        return taint_node_list

'''
def main():
    func_addr = 0x804d4b0
    target_addrs = [0x804d538]
    filename = "netstat"
    c = Construct(filename, func_addr)
    taint_node_list = c.get_data_flow()


if __name__=='__main__':
    main()
'''