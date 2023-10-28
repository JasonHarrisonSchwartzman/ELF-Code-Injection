from elftools import *
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_D_TAG_COMMON

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
    print("dynamic section offset ",dynamic_section_offset)
    for i in range(dynamic_section.num_tags()):
        tag = dynamic_section._get_tag(i)
        tag_value = tag['d_ptr']
        if (ENUM_D_TAG_COMMON[tag['d_tag']] < max_common_tag and tag_value > inject_offset):
            print(tag['d_tag'],dynamic_section._get_tag(i)['d_ptr'])
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


size = 16
f = open('hello','r+b')
elf = ELFFile(open('hello','rb'))
inject_offset = 0x1169

modify_file(f,40,(elf['e_shoff']+16).to_bytes(8,'little'))

edit_text_section(elf,f,inject_offset,size)
edit_elf_sections( elf,f,'.text',size)
edit_symbol_table(elf,f,inject_offset,size)
edit_program_header(elf,f,inject_offset,size)
edit_dynamic_section(elf,f,inject_offset,size)
edit_rela_dyn_section(elf,f,size)