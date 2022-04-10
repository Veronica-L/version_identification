import re
import os
import binascii
import magic
import angr

class Data_info:
    def __init__(self, path):
        self.path = path
        #self._p = angr.Project(self.path, load_options={'auto_load_libs': False})
        self.data_startaddr = 0
        self.info_dict = {} 
        self.variable_map = {}
        self.probable_version_list = []
        self.probable_version_addr_list = []
        self.probable_variable_list = []
        self.probable_version_dict = {}  # {version:addr}
        self.probable_asm_list = []
        self.endian = ''
        self.data_content = ''

        self.asmfile = self.path + '_asm'
        self.datafile = self.path + '_data'
        self.rodatafile = self.path + '_rodata'
        self.readelf = self.path + '_readelf'

        self.text_start_addr = 0
        self.text_size = 0
        self.text_end_addr = 0

    def check_endian(self):
        file_type_info = magic.from_file(self.path)
        if "LSB" in file_type_info:
            self.endian = 'LSB'
        elif "MSB" in file_type_info:
            self.endian = 'MSB'
        else:
            self.endian = ''
    
    def segment_info(self): 
        '''get segment .text start_address and end_address'''
        f = open('tmp/'+self.path+'_readelf', 'r')
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            if line.startswith('[') and line[5:10]=='.text':
                info_list = line.split(' ')
                while '' in info_list:
                    info_list.remove('')
                self.text_start_addr = int(info_list[3],16)
                self.text_size = int(info_list[5],16)
                self.text_end_addr = self.text_start_addr + self.text_size

    def hex2char(self, data): #十六进制转字符串
        #binascii.a2b_hex(hexstr) 
        output = binascii.unhexlify(data)
        return output
    
    def reverse(self, offset):
        #'7f250508' --> 0x0805257f #避免0x10805256d情况:[2:10]
        string = offset
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

    def is_text_addr(self, sub_hex):
        if self.endian == 'LSB':
            addr = self.reverse(sub_hex)
            if addr >= self.text_start_addr and addr <= self.text_end_addr:
                return True
            return False

    def rodata_section_info(self):
        f = open('tmp/'+self.path+'_rodata', 'r')
        lines = f.readlines()

        sub_content = ''
        hex_content = ''
        flag = 0

        for line in lines:
            line = line.strip()
            #print(line)

            if line.startswith('0x') and flag == 0:
                rodata_startaddr = line[2:10]
                rodata_startaddr = int(rodata_startaddr, 16)
                flag = 1
            
            if flag == 1:
                sub_hex_list = line[11:46].split(' ')
                
                for sub_hex in sub_hex_list:
                    if sub_hex == '': continue
                    if self.is_text_addr(sub_hex):
                        sub_hex = '00000000'
                    hex_content += sub_hex
                #sub_hex = line[11:46].replace(' ','')
                #print(sub_hex)
                #hex_content += sub_hex
        #print(hex_content)
        #print(self.hex2char(hex_content))

        split_list = [substr.start() for substr in re.finditer('00', hex_content)]  #search all '00'
        for index, number in enumerate(split_list):
            if number%2 != 0:
                if hex_content[number+1:number+3]=='00':
                    split_list[index] = number+1
                else:
                    split_list[index] = 1
        #print(split_list)

        for i, content_index in enumerate(split_list):
            if content_index == 1:
                continue
            if i == 0:
                sub_content = hex_content[:content_index]
                address = rodata_startaddr + 1

            elif i == len(split_list)-1:
                sub_content = hex_content[content_index+2:]
                address = rodata_startaddr + int(content_index/2) + 1

            else:
                sub_content = hex_content[content_index+2:split_list[i+1]]
                address = rodata_startaddr + int(content_index/2) + 1
                
            #print(address)
            output = self.hex2char(sub_content)
            #if sub_content!= '':
                #print(hex(address), output)

            self.info_dict[address] = output

    def data_section_info(self):
        f = open('tmp/'+self.path+'_data', 'r')
        lines = f.readlines()
        flag = 0 

        for line in lines:
            line = line.strip()

            if line.startswith('0x') and flag == 0:
                self.data_startaddr = line[2:10]
                self.data_startaddr = int(self.data_startaddr, 16)
                flag = 1
            
            if flag == 1:
                sub_addr = line[11:46].replace(' ','')
                self.data_content += sub_addr

    def get_probable_variable_list(self, addr):
        #for addr in self.probable_version_addr_list:
        str_addr = str(hex(addr))[2:]
        new_string = ''
        
        j = len(str_addr)
        if j%2 == 0:
            while j >= 2:
                new_string += str_addr[j-2:j]
                j = j-2
        else:
            while j >= 2:
                new_string += str_addr[j-2:j]
                j = j-2
            new_string += '0'
            new_string += str_addr[0]
        
        if new_string in self.data_content:
            address = self.data_startaddr + int(self.data_content.index(new_string)/2)
            #print(hex(address))
            #self.probable_variable_list.append(address)
            return address
        else:
            #print(hex(addr))
            #self.probable_variable_list.append(addr)
            return addr
        
    def get_asm_addr(self, probable_variable):
        f_asm = open('tmp/'+self.path+'_asm', 'r')
        lines = f_asm.readlines()
        asm_list = []
        for line in lines:
            line = line.strip()
            #for variable in self.probable_variable_list:
            variable = probable_variable
            str_variable = str(hex(variable))
            if str_variable in line:
                asm_addr = int('0x' + line[:7], 16)
                #self.probable_asm_list.append(asm_addr)
                asm_list.append(asm_addr)
        return asm_list

        
    def get_probable_version_addr(self):
        for bytes_value in self.info_dict.values():
            string_value = str(bytes_value,'latin-1')
            
            if re.search('[0-9]{1,6}\.[0-9]{1,6}.*', string_value):
                self.probable_version_list.append(string_value)
                # probable_version_addr: 在rodata里的addr
                probable_version_addr = list(self.info_dict.keys())[list(self.info_dict.values()).index(bytes_value)]
            
                print(hex(probable_version_addr), string_value)
                # probable_variable: 对应的在data段里的addr
                probable_variable = self.get_probable_variable_list(probable_version_addr)

                # probable_asm_addr: probable_variable对应的text段的位置
                probable_asm_addr_list = self.get_asm_addr(probable_variable)

                self.probable_version_dict[string_value] = probable_asm_addr_list

                #self.probable_version_addr_list.append(probable_version_addr)

    def run(self):
        self.check_endian()
        self.segment_info()
        self.rodata_section_info()
        self.data_section_info()
        #self.get_probable_version_addr()
        #self.get_probable_variable_list()
        self.get_probable_version_addr()

        #return self.probable_variable_list
        

