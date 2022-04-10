import idc
import idautils
import idaapi


if __name__ == "__main__":
    ida_auto.auto_wait()
    
    start_address = get_name_ea_simple('main')
    print(hex(start_address))
    '''
    start = idc.get_func_attr(start_address,FUNCATTR_START)
    end = idc.get_func_attr(start_address, FUNCATTR_END)

    curr_addr = start

    while curr_addr <= end:
        opt = print_insn_mnem(curr_addr)
        optrand_0 = print_operand(curr_addr,0)
        optrand_1 = print_operand(curr_addr,1)
        if opt == 'LDR' and optrand_0 == 'R0':
            #print(hex(curr_addr),opt, optrand_0, optrand_1)
            main_func_name = optrand_1[1:]
            print(main_func_name)
            main_address = get_name_ea_simple(main_func_name)
            print(hex(main_address))
        curr_addr = idc.next_head(curr_addr,end)
    '''

    ida_pro.qexit(0)
