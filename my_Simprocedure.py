import angr
from angr import Project,SimProcedure

#hook getopt_long函数
class BugFree(SimProcedure):
    def addr_to_string(self, strlen, addr): #只为取longopt结构体里的地址
        offset_strlen = self.inline_call(strlen, addr)
        length = offset_strlen.max_null_index
        #防止出现后面地址被加进去的情况：'0x7effffffb13a0508'
        if length > 4: 
            length = 4
        offset_expr = self.state.memory.load(addr, length, endness=angr.archinfo.Endness.BE)
        offset_string = self.state.solver.eval(offset_expr, cast_to=int)
        return offset_string
    
    def get_string(self, strlen, addr): #取字符串
        offset_strlen = self.inline_call(strlen, addr)
        length = offset_strlen.max_null_index
        offset_expr = self.state.memory.load(addr, length, endness=angr.archinfo.Endness.BE)
        offset_string = self.state.solver.eval(offset_expr, cast_to=int)
        return offset_string
    
    def int_to_hex_to_string(self, integer):
        #0x76657273696f6e --> version
        return bytes.fromhex(hex(integer)[2:]).decode('utf-8')

    def reverse(self, offset):
        #'7f250508' --> 0x0805257f #避免0x10805256d情况:[2:10]
        string = str(hex(offset))[2:]
        new_string = ''
        
        j = len(string)
        if j%2 == 0:
            while j >= 2:
                new_string += string[j-2:j]
                j = j-2
        else:
            while j >= 2:
                new_string += string[j-2:j]
                j = j-2
            new_string += '0'
            new_string += string[0]
        
        an_integer = int(new_string, 16)
        return an_integer

    def opt(self, strlen, longopts_addr, opt_name):
        flag = 0
        for i in range(1000): #offset, 0, 0, 'V'
            if i%16==0:
                offset = self.addr_to_string(strlen, longopts_addr)
                char = self.addr_to_string(strlen, longopts_addr+12)
                print(hex(offset), hex(char))

                if offset == 0:
                    break

                opt_integer = self.reverse(offset)
                if char>127:
                    char = self.reverse(char)
                print(hex(opt_integer), hex(char))

                opt_integer = self.get_string(strlen, opt_integer)
                opt_string = self.int_to_hex_to_string(opt_integer)
                print(opt_string)
                if opt_string == opt_name:
                    print(opt_string,char)
                    #state.regs.eax = char
                    flag = 1
                    return char

                longopts_addr = longopts_addr + 16
        if flag == 0:
            return 0

    def run(self, argc, argv, optstring, longopts):
        myargv = 'V'
        
        if myargv == "version":
            opt_names = ["version", "V"]
        elif myargv == 'V' or 'v':
            opt_names = ["version", myargv.strip('-')]
        elif myargv == "help":
            opt_names = ["help", "h"]

        for opt_name in opt_names:
            if len(opt_name) == 1:
                #opt_name为1个字符，判断optstring是否包含 V
                #1. 先得到optstring
                optstring_addr = self.state.solver.eval(optstring, cast_to=int)
                strlen = angr.SIM_PROCEDURES['libc']['strlen']
                optstring_strlen = self.inline_call(strlen, optstring_addr)
                print(optstring_strlen.max_null_index)
                optstring_expr = self.state.memory.load(optstring_addr, optstring_strlen.max_null_index, endness=angr.archinfo.Endness.BE)
                optstring_string = self.state.solver.eval(optstring_expr, cast_to=bytes)
                print(optstring_string)
                #2. 判断V是否在optstring中
                if opt_name.encode('utf-8') in optstring_string:
                    #state.regs.eax = ord(opt_name)
                    return ord(opt_name)
            elif len(opt_name) > 1:
                #opt_name为多个字符，判断longopts是否包含version
                longopts_addr = self.state.solver.eval(longopts, cast_to=int)
                print(longopts_addr)
                strlen = angr.SIM_PROCEDURES['libc']['strlen']
                char = self.opt(strlen, longopts_addr, opt_name)
                if char != 0:
                    #state.regs.eax = char
                    return char
        return -1