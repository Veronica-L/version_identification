from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.expression.expression import get_expr_mem, ExprId, ExprInt, ExprOp, ExprMem, ExprLoc
import miasm_v.core.graph as graph
from miasm_v.trackdata.data_analysis_ww_version0 import *
from future.utils import viewitems, viewvalues
import angr
import logging
import os
import re

def print_addr_to_affect2addr(addr_to_affect2addr):
    for i in addr_to_affect2addr.keys():
        print(i)
        for aff in addr_to_affect2addr[i]:
            print('aff.get_node:',aff.get_node())
            for temp in aff.depend_separte.keys():
                print(' '*4,end='')
                print(temp)
                for j in aff.depend_separte[temp]:
                    print(' '*8,end='')
                    print(j)
                # print('')
        print('\n')

def print_affected(affected):
    """[这个print 用来输出 affected_exprmem,affected2addr 结构
    """
    for aff in affected:
        print('aff.get_node:',aff.get_node())
        for temp in aff.depend_separte.keys():
            print(' '*4,end='')
            print(temp)
            for i in aff.depend_separte[temp]:
                print(' '*8,end='')
                print(i)
            print('')
        print('\n')

def print_dependency(dependency):
    for depend in dependency:
        print(depend.get_node(),end='')
        print(':')
        for node in depend.dependency:
            print(' '*4,end='')
            print(node.get_node())
        print('')

def deal_circular_dependencies(dependency):
    for depend in dependency:
        temp_depend=depend.depend_loc_key_line
        temp_depend=list(set(temp_depend))
        temp_node=set([])
        temp_depend.sort()
        for node in depend.dependency:
            temp_node.update(node.depend_loc_key_line)
        temp_node=list(temp_node)
        temp_node.sort()
        if(len(temp_depend)<len(temp_node)):
            depend.depend_loc_key_line=temp_node

def get_node_name(label, i, r_or_w, n,addr,instruction):
    #0: read
    #1: write
    n_name = (str(label), i,r_or_w, n,addr,instruction)
    return n_name

def create_bl_data_flow(block, flow_graph, bl_in_node, bl_out_node):
    for line in block:
        print(line.instr, '\n')
    '''创建数据流'''
    exist_nodes = {}
    for i, bl_line in enumerate(block):
        if bl_line.instr == None: #指令为空
            continue
        instr_wr = bl_line.get_rw() #EBP = ESP {ExprId(‘EBP’, 32): {ExprId(‘ESP’, 32)}}
        instr_addr = bl_line.instr.offset
        print(i, hex(instr_addr), str(bl_line.instr), bl_line, bl_line.get_r(), bl_line.get_rw())

        nodes_r_mem = set()
        # 生成edge：[EBP+0xC] -> {ExprId(‘EBP’, 32), ExprInt(0xC, 32)}
        for node_w, nodes_r in viewitems(instr_wr):
            if 'MOV' in bl_line.instr.name or 'LEA' in bl_line.instr.name:
                break
            for n in nodes_r.union([node_w]):
                nodes_r_mem.update(get_expr_mem(n))
            if not nodes_r_mem:
                continue
            for nn in nodes_r_mem:
                node_n_w = get_node_name(block, i, 1, nn, bl_line.instr.offset, str(bl_line.instr))
                if not nn in nodes_r:
                    continue
                o_r = nn.ptr.get_r(mem_read=False, cst_read=True)
                for n_r in o_r:
                    if n_r in exist_nodes:
                        nr = exist_nodes[n_r]
                    else:
                        nr = get_node_name(block, i, 0, n_r, bl_line.instr.offset, str(bl_line.instr))
                        exist_nodes[n_r] = nr
                        bl_in_node[n_r] = nr
                    flow_graph.add_uniq_edge(nr, node_n_w)

        for node_w, nodes_r in viewitems(instr_wr): #nodes_r: dict
            for nr in nodes_r:
                #为 node_r 创建节点
                if nr not in exist_nodes: 
                    if isinstance(nr, ExprMem):
                        graph_node_r = get_node_name(block.loc_key, i, 1, nr, instr_addr, str(bl_line.instr))
                    else:
                        graph_node_r = get_node_name(block.loc_key, i, 0, nr, instr_addr, str(bl_line.instr))
                    exist_nodes[nr] = graph_node_r
                    bl_in_node[nr] = graph_node_r # 进节点
                else:
                    graph_node_r = exist_nodes[nr]
                flow_graph.add_node(graph_node_r) #graph绘制节点
                

                #为 node_w 创建节点
                graph_node_w = get_node_name(block.loc_key, i, 1, node_w, instr_addr, str(bl_line.instr))
                exist_nodes[node_w] = graph_node_w
                bl_out_node[node_w] = graph_node_w #出节点
                flow_graph.add_node(graph_node_w) #graph绘制节点

                flow_graph.add_uniq_edge(graph_node_r, graph_node_w) #graph绘制edge
            
            track_args=['RAX','RBX','RCX','RDX','EAX','EBX','ECX','EDX','AX','BX','CX','DX']
            # 针对 node_w 是mem的情况 MOV [EAX+0x27C], EBX这种情况 
            if isinstance(node_w, ExprMem):
                #node_w @32[ESP + 0x4] -> write_w: {ExprId('ESP', 32), ExprInt(0x4, 32)}
                write_w = node_w.ptr.get_r(mem_read=False,cst_read=True) 
                write_w = [x for x in write_w if(isinstance(x, ExprId) and x.name in track_args)]
                graph_node_w = get_node_name(block.loc_key, i, 1, node_w, instr_addr, str(bl_line.instr))
                for node in write_w:
                    if node in exist_nodes:
                        graph_node_r = exist_nodes[node]
                        flow_graph.add_uniq_edge(graph_node_r, graph_node_w) #graph绘制edge 

            if 'MOV' in bl_line.instr.name or 'LEA' in bl_line.instr.name:
                for nr in nodes_r:
                    if isinstance(nr, ExprMem):
                        read_from = nr.ptr.get_r(mem_read=False,cst_read=True)
                        read_from = [x for x in read_from if(isinstance(x, ExprId) and x.name in track_args)]
                        graph_node_w = get_node_name(block.loc_key, i, 1, node_w, instr_addr, str(bl_line.instr))
                        graph_node_read_to = get_node_name(block.loc_key, i, 1, nr, instr_addr, str(bl_line.instr))
                        for node in read_from:
                            if node in exist_nodes:
                                graph_node_r = exist_nodes[node]
                                flow_graph.add_uniq_edge(graph_node_r, graph_node_read_to)
                                flow_graph.add_uniq_edge(graph_node_r, graph_node_w)
        #print(flow_graph)
        print('\n')

def get_data_dependency(data):
    node = data[0]
    edge = data[1] #依赖节点 -> 被依赖节点
    print(node, edge)

    dependency = []
    not_track = ['IRDst','RBP',"RSP",'EBP','ESP']
    for node_id in edge.keys():
        # 针对edge里的key，也就是依赖节点 to
        node_key = list(node[node_id])

        #node: 'loc_key_95', 6, 1, ExprId('cf', 1), '0x804d4b9', 'SUB        ESP, 0x284'
        if isinstance(node_key[3], ExprLoc):
            continue
        if isinstance(node_key[3], ExprId) and node_key[3].name in not_track:
            continue
        if isinstance(node_key[3], ExprId) and node_key[3].name in ['of','zf','nf','pf','cf','af']:
            continue
        if isinstance(node_key[3], ExprMem) and isinstance(node_key[3].ptr, ExprOp):
            ptr = node_key[3].ptr
            args = list(ptr.args)
            ebp = ExprId('EBP', 32)
            esp = str(ExprId('ESP', 32))
            if esp in str(node_key[3]):
                if "PUSH" in node_key[5] and "BP" not in node_key[5]:
                    for i in edge[node_id]:
                        node_key1=list(node[i])
                        node_key[3]=node_key1[3]
                else:
                    continue
            if node_key[3] == ExprId("EBP", 32):
                continue
        
        depend = DependencyNode(node_key[0],node_key[1],node_key[2],node_key[3],node_id,node_key[4],node_key[5])
        if depend not in dependency:
            dependency.append(depend)
        else:
            depend = dependency[dependency.index(depend)]

        # 针对edge里的key对应的value，也就是被依赖节点 from
        for i in edge[node_id]:
            depend_node = list(node[i])
            if isinstance(depend_node[3], ExprLoc): continue
            if isinstance(depend_node[3], ExprId) and depend_node[3].name in ['of','zf','nf','pf','cf','af']:
                continue
            
            depend_src = DependencyNode(depend_node[0],depend_node[1],depend_node[2],depend_node[3],depend_node,depend_node[4],depend_node[5])
            if depend_src not in dependency:
                depend.add_dependency(depend_src)
                dependency.append(depend_src)
            else:
                depend_src = dependency[dependency.index(depend_src)]
                depend.add_dependency(depend_src)
        
        dependency.sort()

        #处理dependency列表
    for d in dependency:
        print(d.instr, d.node_id)
        for x in d.dependency:
            print(x.node_id)
    return dependency

def get_affected2addr(data):
    node = data[0]
    edge = data[1] #依赖节点 -> 被依赖节点

    dependency = []
    not_track=['IRDst','RBP',"RSP","ESP","EBP"]

    for node_id in edge.keys():
        # 针对edge里的key，也就是依赖节点 to
        node_key = list(node[node_id])

        #node: 'loc_key_95', 6, 1, ExprId('cf', 1), '0x804d4b9', 'SUB        ESP, 0x284'
        if isinstance(node_key[3], ExprLoc):
            continue
        if isinstance(node_key[3],ExprId) and node_key[3].name in ['of','zf','nf','pf','cf','af']:
            continue
        if(isinstance(node_key[3],ExprId) and node_key[3].name in not_track):
            continue
        if(isinstance(node_key[3],ExprMem) and isinstance(node_key[3].ptr,ExprOp)):
            judge_change=[]            
            ptr=node_key[3].ptr
            args=list(ptr.args)
            ebp=ExprId('EBP', 32)
            esp=str(ExprId('ESP', 32))
            if(esp in str(node_key[3])):
                continue
            if(node_key[3]==ExprId('EBP', 32)):
                continue

        depend = AffectedNodes2addr(node_key[0],node_key[1],node_key[2],node_key[3],node_id,node_key[4],node_key[5])
        if depend not in dependency:
            dependency.append(depend)
        else:
            depend = dependency[dependency.index(depend)]

        # 针对edge里的key对应的value，也就是被依赖节点 from
        for i in edge[node_id]:
            depend_node = list(node[i])
            if isinstance(depend_node[3], ExprLoc): continue
            if isinstance(depend_node[3],ExprId) and depend_node[3].name in ['of','zf','nf','pf','cf','af']: continue
            
            depend_src = AffectedNodes2addr(depend_node[0],depend_node[1],depend_node[2],depend_node[3],depend_node,depend_node[4],depend_node[5])
            if depend_src not in dependency:
                depend.add_dependency(depend_src)
                dependency.append(depend_src)
            else:
                depend_src = dependency[dependency.index(depend_src)]
                depend.add_dependency(depend_src)
        
        dependency.sort()
        #Filter out unsuitable variables
        for depend in dependency:
            key=depend.loc_key
            line_nb=depend.line_nb
            instr=depend.instr
            temp_dependency=set()
            ebp=ExprId('EBP', 32)
            fs=ExprId('FS', 16)
            temp_dependency.update(depend.dependency)
            if(isinstance(instr,ExprMem) and hasattr(instr,'ptr')):
                #print('instr',str((1,instr)))
                if(not hasattr(instr.ptr,'args')):
                    continue
                args=instr.ptr.args
                if(fs in args and len(args)==2):
                    temp_dependency=set()
                else:
                    depend_instr=set()
                    for node in depend.dependency:
                        depend_instr.add(node.instr)
                        if(node.instr==ebp):
                            temp_dependency.remove(node)
                        if(isinstance(node.instr,ExprInt) and node.instr in args):
                            temp_dependency.remove(node)
                    depend_instr=list(depend_instr)
                    if(len(depend_instr)==2 and len(args)==2 and ebp in depend_instr and depend_instr[0] in args and depend_instr[1] in 
                    args):
                        temp_dependency=set()
        depend.dependency=temp_dependency

    return dependency

def get_affected(data):
    node = data[0]
    edge = data[1] #依赖节点 -> 被依赖节点

    dependency = []
    not_track=['IRDst','RBP',"RSP","ESP","EBP"]

    for node_id in edge.keys():
        # 针对edge里的key，也就是依赖节点 to
        node_key = list(node[node_id])

        #node: 'loc_key_95', 6, 1, ExprId('cf', 1), '0x804d4b9', 'SUB        ESP, 0x284'
        if isinstance(node_key[3], ExprLoc):
            continue
        if isinstance(node_key[3],ExprId) and node_key[3].name in ['of','zf','nf','pf','cf','af']:
            continue
        if(isinstance(node_key[3],ExprId) and node_key[3].name in not_track):
            continue
        if(isinstance(node_key[3],ExprMem) and isinstance(node_key[3].ptr,ExprOp)):
            judge_change=[]            
            ptr=node_key[3].ptr
            args=list(ptr.args)
            ebp=ExprId('EBP', 32)
            esp=str(ExprId('ESP', 32))
            if(esp in str(node_key[3])):
                continue
            if(node_key[3]==ExprId('EBP', 32)):
                continue

        depend = AffectedNodes(node_key[0],node_key[1],node_key[2],node_key[3],node_id,node_key[4],node_key[5])
        if depend not in dependency:
            dependency.append(depend)
        else:
            depend = dependency[dependency.index(depend)]

        # 针对edge里的key对应的value，也就是被依赖节点 from
        for i in edge[node_id]:
            depend_node = list(node[i])
            if isinstance(depend_node[3], ExprLoc): continue
            if isinstance(depend_node[3],ExprId) and depend_node[3].name in ['of','zf','nf','pf','cf','af']: continue
            
            depend_src = AffectedNodes(depend_node[0],depend_node[1],depend_node[2],depend_node[3],depend_node,depend_node[4],depend_node[5])
            if depend_src not in dependency:
                depend.add_dependency(depend_src)
                dependency.append(depend_src)
            else:
                depend_src = dependency[dependency.index(depend_src)]
                depend.add_dependency(depend_src)
        
        dependency.sort()
        #Filter out unsuitable variables
        for depend in dependency:
            key=depend.loc_key
            line_nb=depend.line_nb
            instr=depend.instr
            temp_dependency=set()
            ebp=ExprId('EBP', 32)
            fs=ExprId('FS', 16)
            temp_dependency.update(depend.dependency)
            if(isinstance(instr,ExprMem) and hasattr(instr,'ptr')):
                #print('instr',str((1,instr)))
                if(not hasattr(instr.ptr,'args')):
                    continue
                args=instr.ptr.args
                if(fs in args and len(args)==2):
                    temp_dependency=set()
                else:
                    depend_instr=set()
                    for node in depend.dependency:
                        depend_instr.add(node.instr)
                        if(node.instr==ebp):
                            temp_dependency.remove(node)
                        if(isinstance(node.instr,ExprInt) and node.instr in args):
                            temp_dependency.remove(node)
                    depend_instr=list(depend_instr)
                    if(len(depend_instr)==2 and len(args)==2 and ebp in depend_instr and depend_instr[0] in args and depend_instr[1] in 
                    args):
                        temp_dependency=set()
        depend.dependency=temp_dependency

    return dependency

def data_from_where(dependency):
    data_from = {}
    for node in dependency:
        print("node: ", node.instr, node.node_id)
        data_from_addrs = data_from.get(node.addr,set([]))
        for depend in node.depend_loc_key_line:
            print(depend)
            depend = list(depend)
            data_from_addrs.add(depend[2])
        data_from_addrs = list(data_from_addrs)
        data_from_addrs.sort()
        data_from_addrs = set(data_from_addrs)
        data_from[node.addr] = data_from_addrs
    
    return data_from

def get_data_from(data, func_addr, target_addrs):
    dependency = get_data_dependency(data)

    for depend in dependency:
        depend.find_dependency()
    
    #Delete circular data dependency a->b ,b->a
    deal_circular_dependencies(dependency)

    for d in dependency:
        print("node: ", d.instr, d.node_id)
        for x in d.dependency:
            print("dependency: ",x.node_id)

    #Delete circular data dependency a->b ,b->a
    #deal_circular_dependencies(dependency)
    
    data_from = data_from_where(dependency)
    print(data_from)

    track_from_result = []
    for target_addr in target_addrs:
        addr_depend = []
        target_addr = str(hex(target_addr))
        if target_addr in data_from:
            addr_depend = list(data_from[target_addr])
        addr_depend.append(target_addr)
        addr_depend = list(set(addr_depend))
        addr_depend.sort()
        
        data_from_result = TrackResult(func_addr, target_addr)
        data_from_result.set_data_from(addr_depend)
        track_from_result.append(data_from_result)

    print("track_from_result:", track_from_result[0].data_from)
    return track_from_result

def filter_affected_exprmem(affected):
    #Drop the dependency on integers in the data
    not_track=["RBP","RSP","RIP","EBP","ESP","EIP",'of','zf','nf','pf','cf','af']
    for affect in affected:
        temp_dependency=[]
        temp_dependency.extend(affect.dependency)
        #Tracing to [RBP + offset] stops.
        if(len(temp_dependency)==1 and isinstance(temp_dependency[0].instr,ExprInt)):
            affect.dependency=set([])
            continue

        for node in affect.dependency:
            if(isinstance(affect.instr,ExprMem) and  isinstance(node.instr,ExprInt)):
                temp_dependency.remove(node)
            if(isinstance(node.instr,ExprId) and node.instr.name in not_track):
                temp_dependency.remove(node)
        affect.dependency=temp_dependency
    
def repaire_affected_exprmem(affected,affected_exprmem):
    affected_exprmem_map={}
    for exprmem in affected_exprmem:
        affected_exprmem_map[exprmem.get_node()]=exprmem

    for aff in affected:
        if(aff.get_node() in affected_exprmem_map):
            continue
        for node in aff.dependency:
            if(node.get_node() in affected_exprmem_map):
                aff.depend_separte=affected_exprmem_map[node.get_node()].depend_separte
                affected_exprmem.add(aff)

def filter_affected(affected):
    # Only the address of the instruction containing memory in the instruction is processed here
    filter_affected_exprmem(affected)
    affect_exprem=set()
    for affect in affected:
        if(not isinstance(affect.instr,ExprMem)):
            continue
        track_args=['RAX','RBX','RCX','RDX','EAX','EBX','ECX','EDX','AX','BX','CX','DX']
        node_w=affect.instr
        write_w=node_w.ptr.get_r(mem_read=False,cst_read=True)
        write_w=[x for x in write_w if(isinstance(x,ExprId) and x.name in track_args)]
        assembly=affect.assembly
        exprmem=re.findall(r'\[.+\]',assembly)
        exp=list()
        if(len(exprmem)!=0):
            exp=exprmem[0]
        tmep_dependency=set([])
        for node in affect.dependency:
            if(isinstance(node.instr,ExprId) and node.instr.name in track_args 
                and node.instr in write_w):
                tmep_dependency.add(node)
            if(isinstance(node.instr,ExprId) and node.instr.name in exp ):
                tmep_dependency.add(node)
        tmep_dependency.add(affect)
        affect.dependency=tmep_dependency
        affect_exprem.add(affect)
    affect_exprem=list(affect_exprem)
    affect_exprem.sort()
    affect_exprem=set(affect_exprem)
    return affect_exprem

def from_target_get_track_affect_data1(affected):
    data={}
    for aff in affected:
        if("CMP" in aff.assembly):
            temp=data.get(aff.addr,{})
            temp.update(aff.depend_separte)
            data[aff.addr]=temp
        # if('MOV' in aff.assembly or "LEA" in aff.assembly):
        else:
            temp0=data.get(aff.addr,{})
            depend=set()
            if(len(temp0)!=0):
                depend.update(temp0[aff.addr])
            for key in aff.depend_separte.keys():
                depend.update(aff.depend_separte[key])
            temp0[aff.addr]=depend
            data[aff.addr]=temp0
    return data

def from_target_get_track_affect_exprmem_data(affected_exprem):
    data={}
    for affect in affected_exprem:
        temp_expr=data.get(affect.addr,{})
        temp={}
        for key in affect.depend_separte.keys():
            temp[key[4]]=affect.depend_separte[key]
        temp_expr.update(temp)
        data[affect.addr]=temp_expr
    return data

def from_affected_exprem_get_backtrack(affect_exprem):
    data={}
    for affect in affect_exprem:
        temp=data.get(affect.addr,set())
        temp.update(affect.depend_line_addr)
        if(len(temp)!=0):
            data[affect.addr]=temp
    return data

def forward_slice(data, data_from, func_addr, target_addrs, ircfg):
    affected2addr = get_affected2addr(data)
    #print_affected(affected2addr)

    for affect in affected2addr:
        affect.find_dependency()
        
    for a in affected2addr:
        print("a_node: ", a.instr, a.node_id, a.addr)
        for x in a.depend_line:
            print("a_dependency: ", x.node_id)
        print("a_separte: ", a.depend_separte)

        #Deal with the situation that a depends on B and B depends on a.
        if(len(affect.dependency)!=0 and len(affect.depend_line)==0):
            for node in affect.dependency:
                affect.depend_line.update(node.depend_line)
                temp=set()
                for i in node.depend_line:
                    temp.add(i.addr)
                if(node.get_node() not in affect.depend_separte):
                    affect.depend_separte[node.get_node()]=temp
                else:
                    affect.depend_separte[node.get_node()].update(temp)

    #这里是为了去重，合并相同的节点操作，存储对应的地址和AffectedNodes2addr 对象之间的对应关系
    # 这里是为了获取对应地址的依赖关系，刚才处理完的数据是分开的吧相同地址的数据合并到一起
    addr_to_affect2addr={}
    # print_affected(affected2addr)
    for affect in affected2addr:
        temp=addr_to_affect2addr.get(affect.addr,set())
        if(len(affect.depend_separte)!=0):
            temp.add(affect)
            addr_to_affect2addr[affect.addr]=temp
    
    #print_addr_to_affect2addr(addr_to_affect2addr)

    #The data source obtained here is in the form of [RBP + offset]
    affected=get_affected(data)
    print_dependency(affected)

    # 这里的filter 过滤之后就只包含指令中包含[rbp+offset] 这种内存操作的指令地址
    affected_exprmem=filter_affected(affected)
    print("mem:\n")
    #print_dependency(affected_exprmem)

    # 这里只对 [rbp+offset] 这种形式的内存变量跟踪
    for affect in affected_exprmem:
        affect.find_dependency()
    # 这里处理完之后对应的地址不全，需要进行简单的修复如果有地址，
    repaire_affected_exprmem(affected,affected_exprmem)
    print_affected(affected_exprmem)

    # 这里是为了获取指令最终来自哪,获取数据的define,得到如下格式的数据：
    """
    0xf1720
     {'0xf1720': {ExprId('RAX', 64)}}
     这里有些是地址，有些不是地址，这里得注意
    """
    track_affect_data=from_target_get_track_affect_data1(affected2addr)
    print("指令最终来自:\n", track_affect_data)

    # 这里得到的是每个内存[rbp+offset] 的决定值，获取的是每个内存的决定值类似如下形式：
    """
    0xf16f1
     {ExprMem(ExprOp('+', ExprId('RBP', 64), ExprInt(0xFFFFFFFFFFFFFF9C, 64)), 32): {ExprMem(ExprOp('+', ExprId('RBP', 64), ExprInt(0xFFFFFFFFFFFFFF9C, 64)), 32)}}
    """
    track_affect_exprmem_data=from_target_get_track_affect_exprmem_data(affected_exprmem)
    print("有内存的决定值:\n", track_affect_exprmem_data)

    #判断最后跟踪的结果有没有[rax+offset] 这种形式的指令，如果有的话，需要回退跟踪rax的依赖值
    backtrack_addr=from_affected_exprem_get_backtrack(affected_exprmem)
    print("内存[eax+offset]中eax的依赖", backtrack_addr)

    for target_addr in target_addrs:
        target_addr = str(hex(target_addr))
        data_to_track = TrackResult(func_addr,target_addr)
        data_to_track = data_from[data_from.index(data_to_track)]
        #这里获取对应地址要跟踪的数据，获取对应指令的define.
        if target_addr in track_affect_data:
            track_affect_separge=track_affect_data[target_addr]
            track_affect=[]
            for key in track_affect_separge.keys():
                if track_affect_separge[key] not in track_affect:
                    track_affect.append(track_affect_separge[key])
        else:
            track_affect = list()
        
        print("before:",target_addr,track_affect)

        temp_addr=int(target_addr,0)
        current_loc_key = next(iter(ircfg.getby_offset(temp_addr)))
        current_block = ircfg.get_block(current_loc_key)

        cmp_test_mem=False 
        #判断当前指令是否是 cmp 类似的指令 判断是不是需要跟踪[rbp+ offset]类似的指令
        #或者判断 dst 是不是 [] 内存指令
        for i, bl_line in enumerate(current_block):
            if str(hex(bl_line.instr.offset)) == target_addr:
                current_line_index = i
                # 判断类似 mov dst,src   dst 是不是 [rbp+off] 类似内存地址
                dict_rw = bl_line.get_rw(cst_read=True)
                for node_w, nodes_r in viewitems(dict_rw):
                    if isinstance(node_w, ExprMem):
                        cmp_test_mem = True
                        if target_addr not in track_affect_exprmem_data:
                            track_affect=set([])
                            break
                        exprmem_data=track_affect_exprmem_data[target_addr]
                        for key in exprmem_data.keys():
                            track_affect=[exprmem_data[key]]
                            break
                if('CMP' in bl_line.instr.name or 'cmp' in bl_line.instr.name):
                    cmp_test_mem=True
                break

        if not cmp_test_mem:
            bl_line = current_block[current_line_index]
            dict_rw = bl_line.get_rw(cst_read=True)
            track_affect=[]
            for node_w, nodes_r in viewitems(dict_rw):
                if node_w.name in ["RBP","RSP","RIP","EBP","ESP","EIP",'of','zf','nf','pf','cf','af','IRDst']:
                    continue
                if set([node_w]) not in track_affect:
                    track_affect.append(set([node_w]))
                if 'CDQ' in bl_line.instr.name:
                    track_affect.append(nodes_r)
            # 这里是为了处理有循环的情况，当当前节点又循环到自己的时候做的处理
            # 这里不知道是为了处理哪一类特殊情况
            for succs in ircfg.successors_iter(current_loc_key):
                block=ircfg.get_block(succs)
                for assignblk_index, assignblk in enumerate(block):
                    if(str(hex(assignblk.instr.offset))==target_addr):
                        current_loc_key=succs
                        current_line=assignblk_index
                        dict_rw=assignblk.get_rw(cst_read=True)
                        track_affect=[]
                        for node_w,nodes_r in viewitems(dict_rw):
                            if(node_w.name in ["RBP","RSP","RIP","EBP","ESP","EIP",'of','zf','nf','pf','cf','af','IRDst']):
                                continue
                            if(set([node_w]) not in track_affect):
                                track_affect.append(set([node_w]))
                            if('CDQ' in assignblk.instr.name):
                                track_affect.append(nodes_r)
        print("after:",target_addr, track_affect)

        if len(track_affect) == 0:
            data_to_track.set_data_to(set([]))
            continue
        
        data_to=set([])
        data_to_backtrace=set([])

        will_track={}
        will_track[current_loc_key] = track_affect


        

def data_analysis(filename, func_addr, target_addrs):
    with open(filename, "rb") as f:
        buf = f.read()
    container = Container.from_string(buf)
    machine = Machine(container.arch)

    mdis = machine.dis_engine(container.bin_stream, loc_db=container.loc_db, dont_dis_nulstart_bloc=True)
    mdis.follow_call = False

    disasm = mdis.dis_multiblock(func_addr)

    ir_arch_analysis = machine.ira(mdis.loc_db)
    ircfg = ir_arch_analysis.new_ircfg_from_asmcfg(disasm) 

    flow_graph = graph.DiGraph()
    bl_in_nodes = {}
    bl_out_nodes = {}

    #每一个基本块对应一个key（label）
    for label in ircfg.blocks:
        bl_in_nodes[label] = {}
        bl_out_nodes[label] = {}

    nb = 0
    for label, block in viewitems(ircfg.blocks):
        print(label)
        create_bl_data_flow(block, flow_graph, bl_in_nodes[label], bl_out_nodes[label])
        nb += 1
        if nb>=12:
            break
    
    data = flow_graph.get_node_and_edge()
    
    #后向 数据流分析
    data_from = get_data_from(data, func_addr, target_addrs)
    print(data_from)

    #前向数据切片
    #forward_slice(data, data_from, func_addr, target_addrs, ircfg)

    return data_from

def iterate_slice(filename, func_addr, target_addrs, data_from_addr):
    slice_addr = []
    for res in data_from_addr:
        slice_addr += res.data_from
    print("slice_addr: ", slice_addr)

    return slice_addr

def get_cfg(filename, func_addr):
    p = angr.Project(filename, load_options={'auto_load_libs': False})
    cfgcache = filename + ".angr_cfg"
    if os.path.exists(cfgcache):
        cfg = pickle.load(open(cfgcache, 'rb'))
    else:
        cfg = p.analyses.CFGFast()
    function_cfg = cfg.functions[func_addr].graph
    print(cfg)
    return function_cfg

def main():
    func_addr = 0x804d4b0
    target_addrs = [0x804d538]
    filename = "netstat"
    data_from_addr = data_analysis(filename, func_addr, target_addrs)
    #iterate_slice(filename, func_addr, target_addrs, data_from_addr)
    #get_cfg(filename, func_addr)

if __name__=='__main__':
    main()
