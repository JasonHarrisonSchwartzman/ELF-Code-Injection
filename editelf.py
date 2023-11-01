from elftools import *
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_D_TAG_COMMON
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from iced_x86 import *
import os

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
            if (instr.ip == 0x11ac):
                print(hex(operand))
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


size = 16
f = open('hello','r+b')
elf = ELFFile(open('hello','rb'))
inject_offset = 0x1194

modify_file(f,40,(elf['e_shoff']+16).to_bytes(8,'little'))

edit_text_section_calls(elf,f,inject_offset,size)

edit_text_section(elf,f,inject_offset,size)
edit_elf_sections( elf,f,'.text',size)
edit_symbol_table(elf,f,inject_offset,size)
edit_program_header(elf,f,inject_offset,size)
edit_dynamic_section(elf,f,inject_offset,size)
edit_rela_dyn_section(elf,f,size)