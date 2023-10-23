from elftools import *
from elftools.elf.elffile import ELFFile

def modify_file(original_file,offset,data):
    original_file.seek(offset)
    original_file.write(data)

def edit_dynamic_section(elf_object,original_file,size):
    dynamic_section = elf_object.get_section(23)
    print(dynamic_section._get_tag(1)['d_ptr'])
    print(dynamic_section.num_tags())

def edit_program_header(elf_object,original_file,size):
    program_header_offset = elf_object['e_phoff']
    num_segments = elf_object.num_segments()
    dynamic_offset = 6
    offset_offset = 8
    filesz_offset = 32
    memsz_offset = 40
    virtual_offset = 16
    physical_offset = 24
    header_size = elf_object['e_phentsize']
    dynamic_segment = elf_object.get_segment(6)
    load_4 = elf_object.get_segment(4)
    load_5 = elf_object.get_segment(5)
    load_10 = elf_object.get_segment(10)
    load_12 = elf_object.get_segment(12)
    load_3 = elf_object.get_segment(3)
    modify_file(original_file,program_header_offset + dynamic_offset * header_size + offset_offset,(dynamic_segment['p_offset']+size).to_bytes(8,'little'))
    modify_file(original_file,program_header_offset + 4 * header_size + offset_offset,(load_4['p_offset']+size).to_bytes(8,'little'))
    modify_file(original_file,program_header_offset + 5 * header_size + offset_offset,(load_5['p_offset']+size).to_bytes(8,'little'))
    modify_file(original_file,program_header_offset + 10 * header_size + offset_offset,(load_10['p_offset']+size).to_bytes(8,'little'))
    modify_file(original_file,program_header_offset + 12 * header_size + offset_offset,(load_12['p_offset']+size).to_bytes(8,'little'))

    modify_file(original_file,program_header_offset + dynamic_offset * header_size + virtual_offset,(dynamic_segment['p_vaddr']+size).to_bytes(8,'little'))
    modify_file(original_file,program_header_offset + 4 * header_size + virtual_offset,(load_4['p_vaddr']+size).to_bytes(8,'little'))
    modify_file(original_file,program_header_offset + 5 * header_size + virtual_offset,(load_5['p_vaddr']+size).to_bytes(8,'little'))
    modify_file(original_file,program_header_offset + 10 * header_size + virtual_offset,(load_10['p_vaddr']+size).to_bytes(8,'little'))
    modify_file(original_file,program_header_offset + 12 * header_size + virtual_offset,(load_12['p_vaddr']+size).to_bytes(8,'little')) 

    modify_file(original_file,program_header_offset + dynamic_offset * header_size + physical_offset,(dynamic_segment['p_paddr']+size).to_bytes(8,'little'))
    modify_file(original_file,program_header_offset + 4 * header_size + physical_offset,(load_4['p_paddr']+size).to_bytes(8,'little'))
    modify_file(original_file,program_header_offset + 5 * header_size + physical_offset,(load_5['p_paddr']+size).to_bytes(8,'little'))
    modify_file(original_file,program_header_offset + 10 * header_size + physical_offset,(load_10['p_paddr']+size).to_bytes(8,'little'))
    modify_file(original_file,program_header_offset + 12 * header_size + physical_offset,(load_12['p_paddr']+size).to_bytes(8,'little')) 

    modify_file(original_file,program_header_offset + 3 * header_size + filesz_offset,(load_3['p_filesz']+size).to_bytes(8,'little'))
    modify_file(original_file,program_header_offset + 3 * header_size + memsz_offset,(load_3['p_memsz']+size).to_bytes(8,'little'))
    print(num_segments)

def edit_symbol_table(elf_object,original_file,inject_offset,size):
    value_offset = 8
    sym_tab = elf_object.get_section_by_name(".symtab")
    sym_tab_offset = sym_tab['sh_offset']
    sym_size = 24
    num_symbols = sym_tab.num_symbols()
    sym_1 = sym_tab.get_symbol(58)['st_value']
    sym_2 = sym_tab.get_symbol(46)['st_value']
    sym_3 = sym_tab.get_symbol(51)['st_value']
    sym_4 = sym_tab.get_symbol(17)['st_value']
    modify_file(original_file,sym_tab_offset + sym_size * 58 + value_offset,(sym_1+size).to_bytes(8,'little'))
    modify_file(original_file,sym_tab_offset + sym_size * 46 + value_offset,(sym_2+size).to_bytes(8,'little'))
    modify_file(original_file,sym_tab_offset + sym_size * 51 + value_offset,(sym_3+size).to_bytes(8,'little'))
    modify_file(original_file,sym_tab_offset + sym_size * 17 + value_offset,(sym_4+size).to_bytes(8,'little'))
    print(sym_tab_offset)
    print(sym_1)
    print(sym_2)

def edit_elf_section(elf_object,original_file,elf_section,section_index,size):
    
    section_header_table = elf_object['e_shoff']
    section_header_size = elf_object['e_shentsize']
    section_offset_offset = 24
    section_size_offset = 32
    total_section_offset_offset = section_header_table + section_header_size * section_index + section_offset_offset
    total_section_size_offset = total_section_offset_offset + 8
    print("section index " + str(section_index))
    print("section header table " + str(section_header_table))
    print("section header entry size " + str(section_header_size))
    print("total section offset offset " + str(total_section_offset_offset))
                                            # !! IMPORTANT !!
    section_offset = elf_section['sh_offset'] # NOT sh_addr. sh_addr is the logical address of the section
    section_size = elf_section['sh_size']

    #changing offset
    modify_file(original_file,total_section_offset_offset,(size + section_offset).to_bytes(8,'little'))

    #changing size
    #modify_file(original_file,total_section_size_offset,(size + section_size).to_bytes(8,'little'))

    assert(original_file.tell() <= section_header_table + section_header_size * (section_index + 1)) # You've written outside the section


def edit_elf_sections(elf_object,original_file,section,size):
    """ Edits all sections by size after section
    """
    for i in range(elf_object.get_section_index(section)+1,elf_object.num_sections()):
        edit_elf_section(elf_object,original_file,elf_object.get_section(i),i,size)

size = 16
f = open('hello','r+b')
elf = ELFFile(open('hello','rb'))
modify_file(f,40,(elf['e_shoff']+16).to_bytes(8,'little'))
edit_elf_sections( elf,f,'.text',size)
edit_symbol_table(elf,f,0x1194,size)
edit_program_header(elf,f,size)
edit_dynamic_section(elf,f,size)
