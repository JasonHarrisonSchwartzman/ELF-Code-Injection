from elftools import *
from elftools.elf.elffile import ELFFile

ENUM_D_TAG_COMMON = dict(
    DT_NULL=0,
    DT_NEEDED=1,
    DT_PLTRELSZ=2,
    DT_PLTGOT=3,
    DT_HASH=4,
    DT_STRTAB=5,
    DT_SYMTAB=6,
    DT_RELA=7,
    DT_RELASZ=8,
    DT_RELAENT=9,
    DT_STRSZ=10,
    DT_SYMENT=11,
    DT_INIT=12,
    DT_FINI=13,
    DT_SONAME=14,
    DT_RPATH=15,
    DT_SYMBOLIC=16,
    DT_REL=17,
    DT_RELSZ=18,
    DT_RELENT=19,
    DT_PLTREL=20,
    DT_DEBUG=21,
    DT_TEXTREL=22,
    DT_JMPREL=23,
    DT_BIND_NOW=24,
    DT_INIT_ARRAY=25,
    DT_FINI_ARRAY=26,
    DT_INIT_ARRAYSZ=27,
    DT_FINI_ARRAYSZ=28,
    DT_RUNPATH=29,
    DT_FLAGS=30,
    DT_ENCODING=32,
    DT_PREINIT_ARRAY=32,
    DT_PREINIT_ARRAYSZ=33,
    DT_SYMTAB_SHNDX=34,
    DT_RELRSZ=35,
    DT_RELR=36,
    DT_RELRENT=37,
    DT_NUM=38,
    DT_LOOS=0x6000000d,
    DT_ANDROID_REL=0x6000000f,
    DT_ANDROID_RELSZ=0x60000010,
    DT_ANDROID_RELA=0x60000011,
    DT_ANDROID_RELASZ=0x60000012,
    DT_ANDROID_RELR=0x6fffe000,
    DT_ANDROID_RELRSZ=0x6fffe001,
    DT_ANDROID_RELRENT=0x6fffe003,
    DT_ANDROID_RELRCOUNT=0x6fffe005,
    DT_HIOS=0x6ffff000,
    DT_LOPROC=0x70000000,
    DT_HIPROC=0x7fffffff,
    DT_PROCNUM=0x35,
    DT_VALRNGLO=0x6ffffd00,
    DT_GNU_PRELINKED=0x6ffffdf5,
    DT_GNU_CONFLICTSZ=0x6ffffdf6,
    DT_GNU_LIBLISTSZ=0x6ffffdf7,
    DT_CHECKSUM=0x6ffffdf8,
    DT_PLTPADSZ=0x6ffffdf9,
    DT_MOVEENT=0x6ffffdfa,
    DT_MOVESZ=0x6ffffdfb,
    DT_SYMINSZ=0x6ffffdfe,
    DT_SYMINENT=0x6ffffdff,
    DT_GNU_HASH=0x6ffffef5,
    DT_TLSDESC_PLT=0x6ffffef6,
    DT_TLSDESC_GOT=0x6ffffef7,
    DT_GNU_CONFLICT=0x6ffffef8,
    DT_GNU_LIBLIST=0x6ffffef9,
    DT_CONFIG=0x6ffffefa,
    DT_DEPAUDIT=0x6ffffefb,
    DT_AUDIT=0x6ffffefc,
    DT_PLTPAD=0x6ffffefd,
    DT_MOVETAB=0x6ffffefe,
    DT_SYMINFO=0x6ffffeff,
    DT_VERSYM=0x6ffffff0,
    DT_RELACOUNT=0x6ffffff9,
    DT_RELCOUNT=0x6ffffffa,
    DT_FLAGS_1=0x6ffffffb,
    DT_VERDEF=0x6ffffffc,
    DT_VERDEFNUM=0x6ffffffd,
    DT_VERNEED=0x6ffffffe,
    DT_VERNEEDNUM=0x6fffffff,
    DT_AUXILIARY=0x7ffffffd,
    DT_FILTER=0x7fffffff,
    _default_=0xffffffff,
)

def modify_file(original_file,offset,data):
    original_file.seek(offset)
    original_file.write(data)

def edit_rela_plt_section(elf_object,original_file,size):
    rela_plt_section = elf_object.get_section(11)
    rela_plt_section_offset = 0x608
    rela_plt_relo_size = 24
    rela_plt_num_relocations = rela_plt_section.num_relocations()
    for i in range(rela_plt_num_relocations):
        rela_plt_offset = rela_plt_section.get_relocation(i)['r_offset']
        modify_file(original_file,rela_plt_section_offset + i * rela_plt_relo_size,(rela_plt_offset+size).to_bytes(8,'little'))

def edit_rela_dyn_section(elf_object,original_file,size):
    rela_dyn_section = elf_object.get_section(10)
    rela_dyn_section_offset = 0x548
    rela_dyn_relo_size = 24
    rela_dyn_num_relocations = rela_dyn_section.num_relocations()
    rela_dyn_num_relocations = 3
    for i in range(rela_dyn_num_relocations):
        rela_dyn_offset = rela_dyn_section.get_relocation(i)['r_offset']
        modify_file(original_file,rela_dyn_section_offset + i * rela_dyn_relo_size,(rela_dyn_offset+size).to_bytes(8,'little'))


def edit_dynamic_section(elf_object,original_file,size):
    dynamic_section_offset = 0x2dd0
    dynamic_section = elf_object.get_section(23)
    fini_value = dynamic_section._get_tag(1)['d_ptr']
    #print(fini_value)
    #print(dynamic_section.num_tags())
    print()
    for i in range(dynamic_section.num_tags()):
        tag = dynamic_section._get_tag(i)
        tag_value = tag['d_ptr']
        if (ENUM_D_TAG_COMMON[tag['d_tag']] < 30 and tag['d_ptr'] > 0x1169):
            print(tag['d_tag'],dynamic_section._get_tag(i)['d_ptr'])
            modify_file(original_file,dynamic_section_offset + 16 * i + 8,(tag_value+size).to_bytes(8,'little'))

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
    sym_5 = sym_tab.get_symbol(18)['st_value']
    sym_6 = sym_tab.get_symbol(57)['st_value']
    for i in range(num_symbols):
        sym = sym_tab.get_symbol(i)['st_value']
        if (sym > 0x1169):
            modify_file(original_file,sym_tab_offset + sym_size * i + value_offset,(sym+size).to_bytes(8,'little'))
    #modify_file(original_file,sym_tab_offset + sym_size * 58 + value_offset,(sym_1+size).to_bytes(8,'little'))
    #modify_file(original_file,sym_tab_offset + sym_size * 46 + value_offset,(sym_2+size).to_bytes(8,'little'))
    #modify_file(original_file,sym_tab_offset + sym_size * 51 + value_offset,(sym_3+size).to_bytes(8,'little'))
    #modify_file(original_file,sym_tab_offset + sym_size * 17 + value_offset,(sym_4+size).to_bytes(8,'little'))
    #modify_file(original_file,sym_tab_offset + sym_size * 18 + value_offset,(sym_5+size).to_bytes(8,'little'))
    #modify_file(original_file,sym_tab_offset + sym_size * 57 + value_offset,(sym_6+size).to_bytes(8,'little'))
    print(sym_tab_offset)

def edit_elf_section(elf_object,original_file,elf_section,section_index,size):
    
    section_header_table = elf_object['e_shoff']
    section_header_size = elf_object['e_shentsize']
    section_offset_offset = 24
    section_addr_offset = 16
    total_section_addr_offset = section_header_table + section_header_size * section_index + section_addr_offset
    total_section_offset_offset = section_header_table + section_header_size * section_index + section_offset_offset
    total_section_size_offset = total_section_offset_offset + 8
    print("section index " + str(section_index))
    print("section header table " + str(section_header_table))
    print("section header entry size " + str(section_header_size))
    print("total section offset offset " + str(total_section_offset_offset))
                                            # !! IMPORTANT !!
    section_offset = elf_section['sh_offset'] # NOT sh_addr. sh_addr is the logical address of the section
    section_addr = elf_section['sh_addr']
    #changing offset
    modify_file(original_file,total_section_offset_offset,(size + section_offset).to_bytes(8,'little'))

    #changing virtual address
    modify_file(original_file,total_section_addr_offset,(size + section_addr).to_bytes(8,'little'))

    assert(original_file.tell() <= section_header_table + section_header_size * (section_index + 1)) # You've written outside the section

def edit_text_size(elf_object,original_file,size):
    section_header_table = elf_object['e_shoff']
    section_header_size = elf_object['e_shentsize']
    section_size_offset = 32
    text_index = 16
    text_section = elf_object.get_section_by_name(".text")
    text_section_size = text_section['sh_size']
    total_section_size_offset = section_header_table + section_header_size * text_index + section_size_offset
    modify_file(original_file,total_section_size_offset,(text_section_size+size).to_bytes(8,'little'))

def edit_elf_sections(elf_object,original_file,section,size):
    """ Edits all sections by size after section
    """

    for i in range(elf_object.get_section_index(section)+1,elf_object.num_sections()):
        edit_elf_section(elf_object,original_file,elf_object.get_section(i),i,size)

def edit_calls(elf_object,original_file,size):
    csu_fini_offset = 0x1096
    modify_file(original_file,csu_fini_offset,(0xa6).to_bytes(1,'little'))
    csu_init_offset = 0x109d
    modify_file(original_file,csu_init_offset,(0x2f).to_bytes(1,'little'))
    call_offset = 0x10aa
    #modify_file(original_file,call_offset,(0x42).to_bytes(1,'little'))
    modify_file(original_file,0x11ed,(0xfdff).to_bytes(2,'little'))
    modify_file(original_file,0x1022,(0xa2).to_bytes(1,'little'))
    modify_file(original_file,0x1029,(0xa3).to_bytes(1,'little'))
    modify_file(original_file,0x10b3,(0x69).to_bytes(1,'little'))
    modify_file(original_file,0x10ba,(0x62).to_bytes(1,'little'))
    modify_file(original_file,0x10e3,(0x39).to_bytes(1,'little'))
    modify_file(original_file,0x10ea,(0x32).to_bytes(1,'little'))
    modify_file(original_file,0x1126,(0xf5).to_bytes(1,'little'))
    modify_file(original_file,0x113e,(0xd6).to_bytes(1,'little'))
    modify_file(original_file,0x114e,(0xcd).to_bytes(1,'little'))
    #modify_file(original_file,0x100b,(0xe9).to_bytes(1,'little'))

def edit_main(elf_object,original_file,size):
    modify_file(original_file,0x11a4,(0xc9).to_bytes(1,'little'))
    modify_file(original_file,0x1186,(0x8a).to_bytes(1,'little'))
size = 16
f = open('hello','r+b')
elf = ELFFile(open('hello','rb'))
modify_file(f,40,(elf['e_shoff']+16).to_bytes(8,'little'))
edit_text_size(elf,f,size)
edit_elf_sections( elf,f,'.text',size)
edit_symbol_table(elf,f,0x1194,size)
edit_program_header(elf,f,size)
edit_dynamic_section(elf,f,size)
edit_rela_dyn_section(elf,f,size)
#edit_rela_plt_section(elf,f,size)
edit_calls(elf,f,size)
edit_main(elf,f,size)

