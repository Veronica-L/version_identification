from backward_slice import data_analysis

def backward_slice(binfile_path, func_addr, target_addrs):
    # print('Going to process', binfile_path, hex(func_addr), [hex(addr) for addr in target_addrs], '\n')
    try:
        slice_result = data_analysis(binfile_path, func_addr, target_addrs)
    except KeyError as e:
        return []

    # print ('slice_result', slice_result)
    result_addr_list_back = []
    for res in slice_result:
        # res.print_track_result()
        result_addr_list_back += res.data_from
    return result_addr_list_back

def iterate_slice(binfile_path, func_addr, target_addrs: list):
    to_slice_instr_addr = target_addrs
    slice_res_all = []
    while len(to_slice_instr_addr) > 0:
        slice_res = backward_slice(binfile_path, func_addr, to_slice_instr_addr)
        to_slice_instr_addr = []
        for x in slice_res:
            x = int(x, 16)
            if x not in slice_res_all:
                to_slice_instr_addr.append(x)
                slice_res_all.append(x)
    print(slice_res_all)
    return slice_res_all
    '''
    # Map the set of instruction addresses obtained by slicing to a set of basic block addresses
    mapped_block_set = set()
    for slice_addr in slice_res_all:
        for block in func_cfg.blocks:
            if slice_addr in block.get_offsets():
                mapped_block_set.add(block.get_offsets()[0])

    return sorted(mapped_block_set)
    '''

if __name__ == '__main__':
    res = iterate_slice('netstat', func_addr=0x804d4b0, target_addrs=[0x804d533])
    print(",".join([hex(r) for r in res]))