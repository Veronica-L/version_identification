from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.asmblock import AsmBlockBad
from miasm.expression.expression import get_expr_mem, ExprId, ExprInt, compare_exprs
import miasm_v.core.graph as graph
from miasm_v.analysis.data_analysis import intra_block_flow_raw_0
from miasm_v.trackdata.data_analysis_ww_version0 import *
import re


def deal_circular_dependencies(dependency):600
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

def data_from_where(dependency):
    data={}
    for node in dependency:
        data_from=data.get(node.addr,set([]))
        for depend in node.depend_loc_key_line:
            depend=list(depend)
            #print('',depend[2])
            data_from.add(depend[2])
        data_from=list(data_from)
        data_from.sort()
        data_from=set(data_from)
        data[node.addr]=data_from
    
    for node in dependency:
        temp_line=data[node.addr]
        for depend in node.depend_loc_key_line:
            pass
    return data

def track_in_block2(ircfg,loc_key,line_nb,will_track,
                 affect_exprmem_data):
    data_to=set()
    block=ircfg.get_block(loc_key)
    #The data that the entire block will track,He must be dealt with first to see if it is rewritten
    track_data=list(will_track[loc_key])
    track_print=False
    for line,assignblk in enumerate(block[line_nb:]):
        start_addr=assignblk.instr.offset
        break

    is_out_print=False
    # 在当前块内从 line_nb开始遍历指令
    for line,assignblk in enumerate(block[line_nb:]):
        addr=str(hex(assignblk.instr.offset))
        # if(line==line_nb):
        #     print(addr)
        #     print(loc_key)
        #     print('')

        # if(addr=='0xf1639'):
        #     print(addr)
        #     is_out_print=True
        #     print('track_data_before:',track_data)
        #     for i in track_data:
        #         print(" "*4,i)
        #     dict_rw = assignblk.get_rw(cst_read=True)
        #     for node_w, nodes_r in viewitems(dict_rw):
        #         print(('node_w',node_w))
        #         print('     ',nodes_r)
        #     print('')

        #Trace the corresponding register value.
        # 这里判断对应的待跟踪的指令有没有被修改，判断当前指令有没有受到影响，需不需要新加入受到影响的指令等操作
        # 这个函数需要修改
        if(len(track_data)!=0):
            temp_track_data=[]
            dict_rw = assignblk.get_rw(cst_read=True)
            # if(addr=='0xf1639'):
            #     print('0xf1639',dict_rw)
            re_assignment=False
            # 这里遍历 src 指令是否包含跟踪的地址
            for node_w, nodes_r in viewitems(dict_rw):
                # if(addr=='0xf170c'):
                #     print('0xf170c,nodes_r:',nodes_r)
                #     print("node_w:",set([node_w]))
                #     print('track_addr:',track_data)
                #     print("")
               
                # 这里判断指令是否被重写过，如果被重写过需要丢弃t_d
                # mov dst,src
                # src 是否是[rbp+offset] 如果是的话需要去对应的表中查找，对应的依赖，然后在跟踪
                # 如果不是的话这直接使用这个地址来跟踪 ，如果有的话又被影响到的话，需要把当前指令的dst加入，一条指令中只有一个对内存的操作
                # 判断dst 是否有被写过，如果dst 有被写过，则需要重新从修改当中删除

                ''' 判断是否是内存地址,因为一条指令中不可能dst,src 同时为[] ,所以不用在判断src 是否为 []'''
                temp_track_data=[]
                # 这里对dst 进行判断，如果dst 是内存[] 是一种情况,需要特殊处理
                if(type(node_w)==ExprMem ):
                    # if(addr=='0x2f3ec'):
                    #     print(addr)
                    #     print("node_w:",node_w)
                    #     print('node_r:',nodes_r)
                    #     print(assignblk)
                    #     print("")
                    # 这里addr in affect_exprmemt_data 还存在可以改进的地方
                    if(addr in affect_exprmem_data):
                        w_exprmems=affect_exprmem_data[addr]
                        for key in w_exprmems.keys():
                            w_exprmem=w_exprmems[key]
                            break
                        # 这里获取对应的指令的跟踪 
                        for track_t in track_data:
                            if(track_t!=w_exprmem):
                                temp_track_data.append(track_t)
                            else:
                                #这里如果存在修改的话需要判断，如果src 里面也包含需要跟踪的指令则不需要删除
                                #这里不存在一条指令中同时存在两个内存的情况，所以不需要考虑node_r也是内存的情况
                                for n_r in nodes_r:
                                    if(n_r in track_data):
                                        temp_track_data.append(track_t)
                                        break
                else:
                    # 非内存是另一种情况
                    for track_t in track_data:
                        if(set([node_w])!=track_t):
                            temp_track_data.append(track_t)
                        else:
                            #这里存在两种情况，一种是内存，一种是非内存
                            for n_r in nodes_r:
                                if(type(n_r)==ExprMem):
                                    # 这里addr in affect_exprmemt_data 还存在可以改进的地方
                                    if(addr in affect_exprmem_data):
                                        w_exprmems=affect_exprmem_data[addr]
                                        for key in w_exprmems.keys():
                                            w_exprmem=w_exprmems[key]
                                            break
                                        if(w_exprmem in track_data):
                                            temp_track_data.append(track_t)
                                            break
                                        else:
                                            '''
                                            .text:00000000000F1708 mov     rax, [rbp+ndo]
                                            .text:00000000000F170C mov     rax, [rax+0x80]
                                            为了处理这种特殊情况，这里rax被重写了，但是src 包含要跟踪的指令，所以rax 不应该删除，应该继续跟踪
                                            '''
                                            sep_exprmem=n_r.ptr.get_r(mem_read=False,cst_read=True)
                                            for s_e in sep_exprmem:
                                                if(set([s_e]) in track_data):
                                                    temp_track_data.append(track_t)
                                                    break

                                            # if(addr=='0xf170c'):
                                            #     print("sep_exprmem:",sep_exprmem)
                                            #     print("")

                                else:
                                    if(set([n_r]) in track_data):
                                        temp_track_data.append(track_t)
                                        break
                                        
                
                track_data=temp_track_data
                
                #判断当前地址是否受到影响
                for n_r in nodes_r:
                    #[rbp+offset] 这种形式要分开考虑
                    if(type(n_r)==ExprMem):
                        w_exprmems=affect_exprmem_data[addr]
                        for key in w_exprmems.keys():
                            w_exprmem=w_exprmems[key]
                            break
                        #如果存在里面的话需要把dst 加入待跟踪的地址列表里面去
                        if(w_exprmem in track_data):
                            data_to.add(addr)
                            #如果dst是存地址需要额外考虑,不可能在一条指令中出现两个对地址的操作，所以不用考虑dst是内存的情况
                            if(type(node_w)==ExprId and node_w.name in ["RBP","RSP","RIP","EBP","ESP","EIP","cf",'zf','nf','of','IRDst']):
                                    pass
                            elif(type(node_w)==ExprLoc):
                                pass
                            else:
                                # print('node_w:',node_w)
                                track_data.append(set([node_w]))
                        else:
                            '''是内存的时候时候要考虑一种特殊情况：mov     rax, [rax+0x80] 这种特殊情况
                            不仅要判断[rax+0x80] 是否是需要跟踪的，还要判断 rax 是否是需要跟踪的值'''
                            sep_exprmem=n_r.ptr.get_r(mem_read=False,cst_read=True)
                            for s_e in sep_exprmem:
                                if(set([s_e]) in track_data):
                                    data_to.add(addr)
                                    break

                    else:
                        if(set([n_r]) in track_data):
                            data_to.add(addr)
                            if(type(node_w)==ExprMem):
                                # 需要寻找对应的内存地址加入
                                w_exprmems=affect_exprmem_data[addr]
                                for key in w_exprmems.keys():
                                    w_exprmem=w_exprmems[key]
                                    break
                                if(w_exprmem not in track_data):
                                    track_data.append(w_exprmem)
                            else:
                                #直接加入就行
                                if(type(node_w)==ExprId and node_w.name in ["RBP","RSP","RIP","EBP","ESP","EIP","cf",'zf','nf','of','IRDst']):
                                    pass
                                elif(type(node_w)==ExprLoc):
                                    pass
                                else:
                                    track_data.append(set([node_w]))



                # if(addr=='0xf1639'):
                #     print(str(hex(start_addr)))
                #     print('track_data_after:',track_data)
                #     for i in track_data:
                #         print(" "*4,i)
                #     dict_rw = assignblk.get_rw(cst_read=True)
                #     for node_w, nodes_r in viewitems(dict_rw):
                #         print(('node_w',node_w))
                #         print('     ',nodes_r)
                #     print('')

        if(len(track_data)==0):
            break
    # if(is_out_print):
    #     print(str(hex(start_addr)))
    #     print('track_data_after:',track_data)
    #     for i in track_data:
    #         print(" "*4,i)
    #     dict_rw = assignblk.get_rw(cst_read=True)
    #     for node_w, nodes_r in viewitems(dict_rw):
    #         print(('node_w',node_w))
    #         print('     ',nodes_r)
    #     print('')
    data_to=set(data_to)
    return [data_to,track_data]

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

def filter_affected_exprmem(affected):
    #Drop the dependency on integers in the data
    not_track=["RBP","RSP","RIP","EBP","ESP","EIP","cf",'zf','nf']
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

def from_graph_get_dependcy(data):
    #track data
    node=data[0]
    #Which source determines the DST returned
    edge=data[1]

    #There are corresponding dependencies in it
    dependency=[]
    not_track=['IRDst','RBP',"RSP",'EBP','ESP']
    for key in edge.keys():
        node_key=list(node[key])
        if(isinstance(node_key[3],ExprLoc)):
            continue
        if(isinstance(node_key[3],ExprId) and node_key[3].name in not_track):
            continue
        if(isinstance(node_key[3],ExprMem) and isinstance(node_key[3].ptr,ExprOp)):
            judge_change=[]            
            ptr=node_key[3].ptr
            args = list(ptr.args)
            ebp = str(ExprId('EBP', 32))
            esp = str(ExprId('ESP', 32))
            if(esp in str(node_key[3])):
                # continue
                if("PUSH" in node_key[5] and "BP" not in node_key[5]):
                    print(node_key)
                    for i in edge[key]:
                        node_key1=list(node[i])
                        node_key[3]=node_key1[3]
                    print(node_key)
                else:
                    continue
            if(node_key[3]==ExprId('EBP', 32)):
                continue

        depend = DependencyNode(node_key[0],node_key[1],node_key[2],node_key[3],key,node_key[4],node_key[5])
        if(depend not in dependency):
            dependency.append(depend)
        else:
            depend=dependency[dependency.index(depend)]
        
        for i in edge[key]:
            node_key=list(node[i])
            if(isinstance(node_key[3],ExprLoc)):
                continue
            if(isinstance(node_key[3],ExprId) and node_key[3].name in ['of','zf','nf']):
                continue

            depend_src=DependencyNode(node_key[0],node_key[1],node_key[2],node_key[3],i,node_key[4],node_key[5])
            if(depend_src not in dependency):
                depend.add_dependency(depend_src)
                dependency.append(depend_src)
            else:
                depend_src=dependency[dependency.index(depend_src)]
                depend.add_dependency(depend_src)
    
    dependency.sort()
    #Filter out unsuitable variables
    for depend in dependency:
        key=depend.loc_key
        line_nb=depend.line_nb
        instr=depend.instr
        temp_dependency=set()
        rbp=ExprId('EBP', 32)
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
                    if(node.instr==rbp):
                        temp_dependency.remove(node)
                    if(isinstance(node.instr,ExprInt) and node.instr in args):
                        temp_dependency.remove(node)
                depend_instr=list(depend_instr)
                if(len(depend_instr)==2 and len(args)==2 and rbp in depend_instr and depend_instr[0] in args and depend_instr[1] in 
                   args):
                    temp_dependency=set()
        depend.dependency=temp_dependency
    
    return dependency

def from_graph_get_affected2addr(data):
    #track data
    node=data[0]
    #Which source determines the DST returned
    edge=data[1]

    #There are corresponding dependencies in it
    dependency=[]
    not_track=['IRDst','RBP',"RSP", 'EBP','ESP']
    
    #Filter operation
    for key in edge.keys():
        node_key=list(node[key])
        if(isinstance(node_key[3],ExprLoc)):
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

        depend=AffectedNodes2addr(node_key[0],node_key[1],node_key[2],node_key[3],key,node_key[4],node_key[5])
        if(depend not in dependency):
            dependency.append(depend)
        else:
            depend=dependency[dependency.index(depend)]
        
        for i in edge[key]:
            node_key=list(node[i])
            if(isinstance(node_key[3],ExprLoc)):
                continue
            if(isinstance(node_key[3],ExprId) and node_key[3].name in ['of','zf','nf']):
                continue

            depend_src=AffectedNodes2addr(node_key[0],node_key[1],node_key[2],node_key[3],i,node_key[4],node_key[5])
            if(depend_src not in dependency):
                depend.add_dependency(depend_src)
                dependency.append(depend_src)
            else:
                depend_src=dependency[dependency.index(depend_src)]
                depend.add_dependency(depend_src)     
            

    # print_dependency(dependency)
    dependency.sort()
    #Filter out unsuitable variables
    for depend in dependency:
        key=depend.loc_key
        line_nb=depend.line_nb
        instr=depend.instr
        temp_dependency=set()
        rbp=ExprId('EBP', 32)
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
                    if(node.instr==rbp):
                        temp_dependency.remove(node)
                    if(isinstance(node.instr,ExprInt) and node.instr in args):
                        temp_dependency.remove(node)
                depend_instr=list(depend_instr)
                if(len(depend_instr)==2 and len(args)==2 and rbp in depend_instr and depend_instr[0] in args and depend_instr[1] in 
                   args):
                    temp_dependency=set()
        depend.dependency=temp_dependency

    return dependency

def from_graph_get_affected(data):
    #track data
    node=data[0]
    #Which source determines the DST returned
    edge=data[1]

    #There are corresponding dependencies in it
    dependency=[]
    not_track=['IRDst','RBP',"RSP"]

    #Filter operation
    for key in edge.keys():
        node_key=list(node[key])
        if(isinstance(node_key[3],ExprLoc)):
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

        depend=AffectedNodes(node_key[0],node_key[1],node_key[2],node_key[3],key,node_key[4],node_key[5])
        if(depend not in dependency):
            dependency.append(depend)
        else:
            depend=dependency[dependency.index(depend)]
        
        for i in edge[key]:
            node_key=list(node[i])
            if(isinstance(node_key[3],ExprLoc)):
                continue
            if(isinstance(node_key[3],ExprId) and node_key[3].name in ['of','zf','nf']):
                continue

            depend_src=AffectedNodes(node_key[0],node_key[1],node_key[2],node_key[3],i,node_key[4],node_key[5])
            if(depend_src not in dependency):
                depend.add_dependency(depend_src)
                dependency.append(depend_src)
            else:
                depend_src=dependency[dependency.index(depend_src)]
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

def get_depend_from(target_addrs,data,func_addr):
    dependency=from_graph_get_dependcy(data)

    for depend in dependency:
        depend.find_dependency()
    
    #Delete circular data dependency a->b ,b->a
    deal_circular_dependencies(dependency)

    #Get the source of data in the form of {addr: set ([])}
    data_from=data_from_where(dependency)
    print(data_from)

    track_from_result=[]
    for target_addr in target_addrs:
        data1=[]
        target_addr=str(hex(target_addr))
        if(target_addr in data_from):
            data1=list(data_from[target_addr])
        data1.append(target_addr)
        data1=list(set(data1))
        data1.sort()
        from_result=TrackResult(func_addr,target_addr)
        from_result.set_data_from(data1)
        track_from_result.append(from_result)
    
    return track_from_result

def get_depend_to(target_addrs,data,ircfg,data_track,func_addr):
    affected2addr=from_graph_get_affected2addr(data)

    for affect in affected2addr:
        affect.find_dependency()
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
    
    addr_to_affect2addr={}
    # print_affected(affected2addr)
    for affect in affected2addr:
        temp=addr_to_affect2addr.get(affect.addr,set())
        if(len(affect.depend_separte)!=0):
            temp.add(affect)
            addr_to_affect2addr[affect.addr]=temp

    # print_addr_to_affect2addr(addr_to_affect2addr)
    #The data source obtained here is in the form of [RBP + offset]
    affected=from_graph_get_affected(data)
    #这里的affected 是 AffectedNodes 结构,里面存储相应节点的依赖，相当于链表存储结构
    # print_dependency(affected)
    # 这里的filter 过滤之后就只包含指令中包含[rbp+offset] 这种内存操作的指令地址
    affected_exprmem=filter_affected(affected)
    # print_dependency(affected_exprmem)

    # 这里只对 [rbp+offset] 这种形式的内存变量跟踪
    for affect in affected_exprmem:
        affect.find_dependency()

    # 这里处理完之后对应的地址不全，需要进行简单的修复如果有地址，
    repaire_affected_exprmem(affected,affected_exprmem)

    track_affect_data=from_target_get_track_affect_data1(affected2addr)

    track_affect_exprmem_data=from_target_get_track_affect_exprmem_data(affected_exprmem)
    #判断最后跟踪的结果有没有[rax+offset] 这种形式的指令，如果有的话，需要回退跟踪rax的依赖值
    backtrack_addr=from_affected_exprem_get_backtrack(affected_exprmem)

    for target_addr in target_addrs:
        
        target_addr=str(hex(target_addr))
        data_to_track=TrackResult(func_addr,target_addr)
        data_to_track=data_track[data_track.index(data_to_track)]
        #Track_effect is the instruction register or memory to trace.
        #这里获取对应地址要跟踪的数据，获取对应指令的define.
        if(target_addr in track_affect_data):
            track_affect_separge=track_affect_data[target_addr]
            track_affect=[]
            for key in track_affect_separge.keys():
                if(track_affect_separge[key] not in track_affect):
                    track_affect.append(track_affect_separge[key])
        else:
            track_affect=list()   

        temp_addr=int(target_addr,0)
        # print("before:",target_addr,track_affect)
        current_loc_key = next(iter(ircfg.getby_offset(temp_addr)))
        current_block = ircfg.get_block(current_loc_key)
        #print(type(current_block))
        #If it is a test, CMP instruction, or the instruction
        #contains operations on memory, the memory needs to be tracked.
        cmp_test_mem=False 
        # if target_addr not in track_affect_exprmem_data:
        #     continue
        # 这里主要是为了调试使用

        #First, trace in the block where the destination address is located
        #判断当前指令是否是 cmp 类似的指令 判断是不是需要跟踪[rbp+ offset]类似的指令
        #或者判断 dst 是不是 [] 内存指令
        for assignblk_index, assignblk in enumerate(current_block):
            if str(hex(assignblk.instr.offset)) == target_addr:
                current_line=assignblk_index
                #Determine whether the instruction to be tracked is in the form of [RBP + off]
                # 判断类似 mov dst,src   dst 是不是 [rbp+off] 类似内存地址
                dict_rw=assignblk.get_rw(cst_read=True)
                for node_w,node_r in viewitems(dict_rw):
                    if(isinstance(node_w,ExprMem)):
                        cmp_test_mem=True
                        if(target_addr not in track_affect_exprmem_data):
                            track_affect=set([])
                            break;
                            #  这里是为了解决 target 包含内存操作，但是没有解析出来的情况，可能存在bug
                        #print(target_addr)
                        exprmem_data=track_affect_exprmem_data[target_addr]
                        for key in exprmem_data.keys():
                            track_affect=[exprmem_data[key]]
                            break
                # if('TEST' in assignblk.instr.name or 'CMP' in assignblk.instr.name):
                if('CMP' in assignblk.instr.name or 'cmp' in assignblk.instr.name):
                    cmp_test_mem=True
                break
        
        # If not, trace the register directly, such as rax
        #如果不是 cmp 类似的指令，则直接跟踪对应的寄存器，不用按照对应的define来进行跟踪。
        if(not cmp_test_mem):
            assignblk=current_block[current_line]
            dict_rw=assignblk.get_rw(cst_read=True)
            track_affect=[]
            for node_w,nodes_r in viewitems(dict_rw):
                if(node_w.name in ["RBP","RSP","RIP","cf",'zf','nf','IRDst']):
                    continue
                if(set([node_w]) not in track_affect):
                    track_affect.append(set([node_w]))
                if('CDQ' in assignblk.instr.name):
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
                            if(node_w.name in ["RBP","RSP","RIP","cf",'zf','nf','IRDst']):
                                continue
                            if(set([node_w]) not in track_affect):
                                track_affect.append(set([node_w]))
                            if('CDQ' in assignblk.instr.name):
                                track_affect.append(nodes_r)


        # print("after:",target_addr,track_affect)
        # print("")
        if(len(track_affect)==0):
            data_to_track.set_data_to(set([]))
            continue
        
        data_to=set([])
        data_to_backtrace=set([])

        #loc_key:[[],[]] this form 
        will_track={}
        will_track[current_loc_key]=track_affect
        # print("will_track:",will_track)
        
        # for i in (track_affect):
        #     print(i)
        # print('')

        #In block tracking, breadth first search is used to transfer tracking results to the next block
        # 先在当前block跟踪，得到往下一个Block 传递的数据
        """[track_affect_data: 这里保存的是每个地址的指令的define
            track_affect_exprmem_data:这里得到的是每个内存[rbp+offset] 的决定值，这里解析的是指令中有内存地址的指令
            addr_to_affect2addr: 这里保存的是每个地址的define   
        """
        # track_block_result=track_in_block2(ircfg,current_loc_key,current_line+1,will_track,
        #             track_affect_data,track_affect_exprmem_data,addr_to_affect2addr)
        track_block_result=track_in_block2(ircfg,current_loc_key,current_line+1,will_track,track_affect_exprmem_data)
        data_to.update(track_block_result[0])
        # print(track_block_result[1])
        todo=list()
        for succs in ircfg.successors_iter(current_loc_key):
            todo.append(succs)
            w_r=will_track.get(succs,list())
            for w_t in track_block_result[1]:
                if(w_t not in w_r):
                    w_r.append(w_t)
            will_track[succs]=w_r        
        
        if(len(track_block_result[1])==0):
            data_to_track.set_data_to(data_to)
            continue

        resolved=set()

        while todo:
            loc_key=todo.pop(0)
            if(loc_key in resolved):
                continue
            resolved.add(loc_key)
            # track_data_result=track_in_block2(ircfg,loc_key,0,will_track,
                    # track_affect_data,track_affect_exprmem_data,addr_to_affect2addr)
            track_data_result=track_in_block2(ircfg,loc_key,0,will_track,track_affect_exprmem_data)
            data_to.update(track_data_result[0])
            if(len(track_data_result[1])==0):
                continue
            for succs in ircfg.successors_iter(loc_key):
                todo.append(succs)
                w_r=will_track.get(succs,list())
                for w_t in track_data_result[1]:
                    if(w_t not in w_r):
                        w_r.append(w_t)
                will_track[succs]=w_r
                # print(succs,w_r)
            #print(str(succs),succs,type(succs))
        
        data_to=list(data_to)
        data_to.sort()
        
        #Determine whether the current instruction contains registers requiring backtracking, such as [rax + offset]
        for addr in data_to:
            if(addr in backtrack_addr):
                data_to_backtrace.update(backtrack_addr[addr])

        data_to=set(data_to)
        data_to.add(target_addr)
        data_to.update(data_to_backtrace)
        data_to=list(set(data_to))
        data_to.sort()
        data_to_track.set_data_to(data_to)
    print(data_to_track)
    return data_track

def gen_block_data_flow_graph(ir_arch, ircfg, ad, target_addr):
    #Determine whether the current block exists
    irblock_0 = None
    for irblock in viewvalues(ircfg.blocks):
        loc_key = irblock.loc_key
        #get the block offset
        offset = ircfg.loc_db.get_location_offset(loc_key)
        if offset == ad:
            irblock_0 = irblock
            break
    assert irblock_0 is not None
    flow_graph = graph.DiGraph()
    #flow_graph.node2str = node2str()

    irb_in_nodes = {}
    irb_out_nodes = {}
    temp=''
    for label in ircfg.blocks:
        irb_in_nodes[label] = {}
        irb_out_nodes[label] = {}
        if(label.key==1085):
            temp=label

    for label, irblock in viewitems(ircfg.blocks):
        """ Create data flow for an irbloc using raw IR expressions """
        intra_block_flow_raw_0(ir_arch, ircfg, flow_graph, irblock, irb_in_nodes[label], irb_out_nodes[label])
        
    #inter_block_flow(ir_arch, ircfg, flow_graph, irblock_0.loc_key, irb_in_nodes, irb_out_nodes)

    data = flow_graph.get_node_and_edge()
        #data = flow_graph
    data_from=get_depend_from(target_addr,data,ad)

    data_result=get_depend_to(target_addr,data,ircfg,data_from,ad)

    return data_result


def data_analysis(FileName, func_addr, target_addrs):
    ad = func_addr

    cont = Container.from_stream(open(FileName, 'rb'))
    machine = Machine(cont.arch)

    mdis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db, dont_dis_nulstart_bloc=True)
    mdis.follow_call = False

    asmcfg = mdis.dis_multiblock(ad)
    if(len(asmcfg.blocks)>0):
        blocks=list(asmcfg.blocks)
        #print(blocks)
        block_1=blocks[0]
        if(isinstance(block_1, AsmBlockBad)):
            bad_result=TrackResult(func_addr,'miasm cannt disassembly')
            bad_result.set_data_from([])
            bad_result.set_data_to([])
            print(bad_result)
            return [bad_result]
    
    #处理间接跳转
    indirect_jmp={}
    for block in asmcfg.blocks:
        if(len(block.lines)==0):
            continue
        instr=block.lines[len(block.lines)-1]
        if(len(instr.args)>0 and isinstance(instr.args[0],ExprId) and (instr.name=='JMP' or instr.name=='jmp') and block.get_next()==None):
            indirect_jmp[block.lines[0].offset]=instr.offset
    
    ir_arch_analysis = machine.ira(mdis.loc_db)
    ircfg = ir_arch_analysis.new_ircfg_from_asmcfg(asmcfg)

    trackResult = gen_block_data_flow_graph(ir_arch_analysis, ircfg, ad, target_addrs)

    return trackResult

def main():
    func_addr = 0x804d4b0
    target_addrs = [0x804d4e0]
    FileName = "netstat"
    data_analysis(FileName, func_addr, target_addrs)

if __name__=='__main__':
    main()