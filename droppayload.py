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


def edit_elf_section(elf_section,section_index,size):   

    total_section_addr_offset = SECTION_HEADER_TABLE_OFFSET + SECTION_HEADER_TABLE_ENTRY_SIZE * section_index + SECTION_HEADER_VIRTUAL_ADDRESS_STRUCT_OFFSET
    total_section_offset_offset = SECTION_HEADER_TABLE_OFFSET + SECTION_HEADER_TABLE_ENTRY_SIZE * section_index + SECTION_HEADER_FILE_OFFSET_STRUCT_OFFSET
    section_offset = elf_section['sh_offset'] 
    section_addr = elf_section['sh_addr']

    modify_file(total_section_offset_offset,(size + section_offset).to_bytes(8,'little'))
    modify_file(total_section_addr_offset,(size + section_addr).to_bytes(8,'little'))

def get_indices_of_sections():
    indices = []
    for i in range(len(ELF_SECTIONS_CHANGES)):
        indices.append(ELF.get_section_index(ELF_SECTIONS_CHANGES[i]))
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

def edit_elf_sections():
    """ Edits all sections by size after section
    """
    indices = get_indices_of_sections()
    for i in range(ELF.num_sections()):
        size = get_total_increased_offset(indices,i,ELF_SECTIONS_ALIGNMENT_SIZES)
        edit_elf_section(ELF.get_section(i),i,size)

def get_program_header_size_ammount(indices,offset,p_header_size,section_sizes):
    total_size = 0
    for i in range(len(indices)):
        if indices[i] >= offset and indices[i] < offset + p_header_size:
            total_size+=section_sizes[i]
    return total_size
    

def edit_program_header():
    for i in range(NUM_SEGMENTS):
        segment = ELF.get_segment(i)
        segment_offset = PROGRAM_HEADER_OFFSET + i * PROGRAM_HEADER_ENTRY_SIZE
        seg_inject_size = get_program_header_size_ammount(SECTIONS_OFFSETS,segment['p_offset'],segment['p_filesz'],ELF_SECTIONS_ALIGNMENT_SIZES)

        modify_file(segment_offset + PROGRAM_HEADER_FILESZ_STRUCT_OFFSET,(segment['p_filesz']+seg_inject_size).to_bytes(8,'little'))
        modify_file(segment_offset + PROGRAM_HEADER_MEMSZ_STRUCT_OFFSET,(segment['p_memsz']+seg_inject_size).to_bytes(8,'little'))

        increased_offset = get_total_increased_offset(SECTIONS_OFFSETS,segment['p_offset'],ELF_SECTIONS_ALIGNMENT_SIZES)
        modify_file(segment_offset + PROGRAM_HEADER_FILE_OFFSET_STRUCT_OFFSET,(segment['p_offset']+increased_offset).to_bytes(8,'little'))
        modify_file(segment_offset + PROGRAM_HEADER_VIRTUAL_ADDRESS_STRUCT_OFFSET,(segment['p_vaddr']+increased_offset).to_bytes(8,'little'))
        modify_file(segment_offset + PROGRAM_HEADER_PHYSICAL_ADDRESS_STRUCT_OFFSET,(segment['p_paddr']+increased_offset).to_bytes(8,'little'))


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



def edit_symbol_table():

    indices = get_indices_of_sections()
    for i in range(NUM_SYMBOLS):
        sym_value = SYM_TAB_SECTION.get_symbol(i)['st_value']

        section_index = get_section_index_of_virtual_offset(sym_value)
        if section_index is None:
            continue
        increased_size = get_increased_size_after_section(indices,0,ELF_SECTIONS_ALIGNMENT_SIZES,section_index)
        
        size = calculate_new_offset_of_constant_section(sym_value,ELF_SECTIONS_CHANGES,ELF_SECTIONS_ALIGNMENT_SIZES)
        if size is None or increased_size is None:
            continue
        modify_file(SYM_TAB_OFFSET + SYM_TAB_ENTRY_SIZE * i + SYM_TAB_VALUE_STRUCT_OFFSET,(sym_value+increased_size).to_bytes(8,'little'))

def edit_dynamic_section():
    print("-------EDITING DYNAMIC SECTION--------")
    indices = get_indices_of_sections()
    for i in range(DYNAMIC_SECTION.num_tags()):
        tag = DYNAMIC_SECTION._get_tag(i)
        tag_value = tag['d_ptr']
        d_tag = tag['d_tag']
        #print(tag)
        #print(tag_value)
        #print(d_tag)
        new_value = 0x0
        print(tag)
        unchanged = ['DT_NULL','DT_NEEDED','DT_RELAENT','DT_SYMENT','DT_INIT_ARRAYSZ','DT_FINI_ARRAYSZ','DT_DEBUG','DT_FLAGS','DT_FLAGS_1','DT_PLTREL','DT_RELACOUNT','DT_RELASZ']
        if (d_tag in unchanged):
            continue
        elif (d_tag == 'DT_STRSZ'):
            new_value = tag_value + len(str_tab_entries)
        elif (d_tag == 'DT_PLTRELSZ'):
            rela_plt_entry_size = 24
            new_value = len(symbol_names) * rela_plt_entry_size + tag_value
        elif (d_tag == 'DT_VERNEEDNUM'):
            new_value = 2 # hardcoded need to change
        else:
            virtual_offset = get_section_index_of_virtual_offset(tag_value)
            new_value = get_total_increased_offset(indices,virtual_offset,ELF_SECTIONS_ALIGNMENT_SIZES) + tag_value
        
        modify_file(DYNAMIC_SECTION_OFFSET + DYNAMIC_SECTION_ENTRY_SIZE * i + DYNAMIC_SECTION_VALUE_STRUCT_OFFSET,(new_value).to_bytes(8,'little'))

def get_section_index_of_offset(offset):
    for i in range(ELF.num_sections()):
        section = ELF.get_section(i)
        if offset >=section['sh_offset'] and offset < (section['sh_offset'] + section['sh_size']):
            return i
    return None

def get_section_index_of_virtual_offset(offset):
    for i in range(ELF.num_segments()):
        segment = ELF.get_segment(i)
        if offset >= segment['p_vaddr'] and offset < (segment['p_vaddr'] + segment['p_memsz']):
            offset = offset - (segment['p_vaddr'] - segment['p_offset'])
            return get_section_index_of_offset(offset)
    return None

def edit_rela_dyn_section():

    indices = get_indices_of_sections()
    relocation_offset = RELA_DYN_SECTION_OFFSET
    for i in range(RELA_DYN_NUM_RELOCATIONS):


        rela_dyn_relocation_offset = RELA_DYN_SECTION.get_relocation(i)['r_offset']
        section_index = get_section_index_of_virtual_offset(rela_dyn_relocation_offset)

        increased_size = get_increased_size_after_section(indices,0,ELF_SECTIONS_ALIGNMENT_SIZES,section_index)
        modify_file(relocation_offset,(rela_dyn_relocation_offset + increased_size).to_bytes(8,'little'))
        relocation_offset = relocation_offset + RELA_DYN_ENTRY_SIZE
        if RELA_DYN_SECTION.get_relocation(i)['r_info'] != RELATIVE_TYPE:
            continue
        
        print(RELA_DYN_SECTION.get_relocation(i))
        relocation_addend = RELA_DYN_SECTION.get_relocation(i)['r_addend']
        section_index = get_section_index_of_virtual_offset(relocation_addend)
        new_offset = get_increased_size_after_section(indices,0,ELF_SECTIONS_ALIGNMENT_SIZES,section_index)+relocation_addend

        modify_file(RELA_DYN_SECTION_OFFSET + i * RELA_DYN_ENTRY_SIZE + RELA_DYN_ADDEND_STRUCT_OFFSET,(new_offset).to_bytes(8,'little'))
        

def offset_in_rela(offset):
    rela_dyn_section = ELF.get_section_by_name(".rela.dyn")
    rela_dyn_num_relocations = rela_dyn_section.num_relocations()
    relative_type = 8

    rela_plt_section = ELF.get_section_by_name(".rela.plt")
    rela_plt_num_relocations = rela_plt_section.num_relocations()

    for i in range(rela_dyn_num_relocations):
        if offset == rela_dyn_section.get_relocation(i)['r_offset'] and rela_dyn_section.get_relocation(i)['r_info'] != relative_type:
            return True
    for i in range(rela_plt_num_relocations):
        if offset == rela_plt_section.get_relocation(i)['r_offset']:
            return True
    return False


def edit_code_section(section_offset,section_size,inject_offset,size):
    start = section_offset
    end = section_offset + section_size

    FILE.seek(start)  # Move the file pointer to the starting offset
    code = FILE.read(end - start)
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
        if ((instr.ip < inject_offset < rel_mem) or (rel_mem < inject_offset < instr.ip)) and rel_mem < os.path.getsize(FILE_NAME) and not offset_in_rela(rel_mem):
            searching_bytes = operand.to_bytes(4, byteorder='little',signed=True)
            hex_code = ' '.join(f'{byte:02X}' for byte in instruction_bytes)
            hex_bytes = bytes.fromhex(hex_code)
            try:
                instruction_offset = instr.ip + hex_bytes.index(searching_bytes)
            except:
                continue
            modify_file(instruction_offset,(rel_mem - next_ip + size if instr.ip < inject_offset < rel_mem else rel_mem - next_ip - size).to_bytes(4,'little',signed=True))
            #print(hex(instr.ip),"|",disasm,hex(rel_mem),"|"," Next instruction: ",hex(next_ip),"|"," Operand ",hex(rel_mem - next_ip)," | Memory offset",hex(instruction_offset)," | Hex Code: ",hex_code)

def edit_text_section_calls(text_offset,ELF_SECTIONS_ALIGNMENT_SIZES):
    get_new_text_offset = calculate_new_offset_of_constant_section(text_offset,ELF_SECTIONS_CHANGES,ELF_SECTIONS_ALIGNMENT_SIZES)
    for i in range(ELF.num_segments()):
        if ELF.get_segment(i)['p_flags'] & 0x1 == 1:
            offset = ELF.get_segment(i)['p_offset']
            end = offset + ELF.get_segment(i)['p_filesz']
            for i in range(ELF.num_sections()):
                if ELF.get_section(i)['sh_offset'] >= offset and ELF.get_section(i)['sh_offset'] < end:
                    inject_offset = 0x0
                    size = 0x0
                    edit_code_section(ELF.get_section(i)['sh_offset'],ELF.get_section(i)['sh_size'],inject_offset,size)



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

def align_section(offset,num_bytes):
    sizes = []
    bytes_to_add = []
    for i in range(num_bytes):
        sizes.append(1)
        bytes_to_add.append(0x0)
    add_contents_to_file(offset,bytes_to_add,sizes)

def add_functions_to_sym_tab():
    section = ELF.get_section_by_name(".symtab")
    offset = section['sh_offset'] + section['sh_size']
    sizes = [4,1,1,2,8,8]
    assert sum(sizes) * len(symbol_names) == SYM_TAB_INJECT_SIZE, "values are not equal"
    for i in range(len(symbol_names)):
        name = 0x0
        #print(hex(offset))
        add_contents_to_file(offset,[name,0x12,0x0,0x0,0x0,0x0],sizes)
        offset+= section['sh_entsize']
    num_bytes_to_align = SYM_TAB_ALIGNMENT_SIZE - SYM_TAB_INJECT_SIZE
    if num_bytes_to_align > 0:
        align_section(offset,num_bytes_to_align)


def check_duplicate_symbols_and_versions():
    ## Versions

    gnu_version_r_section = ELF.get_section_by_name(".gnu.version_r")
    print(gnu_version_r_section.get_version(2)[1].entry)
    if gnu_version_r_section.get_version(2) is not None:
        GLIBC_versions.remove(gnu_version_r_section.get_version(2)[1].name)
        string_names.remove(gnu_version_r_section.get_version(2)[1].name)
    if gnu_version_r_section.get_version(3) is not None:
        GLIBC_versions.remove(gnu_version_r_section.get_version(3)[1].name)
        string_names.remove(gnu_version_r_section.get_version(3)[1].name)

    ## Symbols
    dyn_sym_tab = ELF.get_section_by_name(".dynsym")
    num_symbols = dyn_sym_tab.num_symbols()
    for i in range(num_symbols):
        if dyn_sym_tab.get_symbol(i).name in symbol_names:
            del sym_versions[(symbol_names.index(dyn_sym_tab.get_symbol(i).name))]
            symbol_names.remove(dyn_sym_tab.get_symbol(i).name)
            string_names.remove(dyn_sym_tab.get_symbol(i).name)

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

def get_index_of_symbol_in_dyn_sym(symbol_name):
    if symbol_name in DYN_SYM_SYMBOL_NAMES:
        return DYN_SYM_SYMBOL_NAMES.index(symbol_name)
    return len(DYN_SYM_SYMBOL_NAMES) + symbol_names.index(symbol_name)

def calculate_got_virtual_address_change():
    section = ELF.get_section_by_name('.got')
    for i in range(ELF.num_segments()):
        segment = ELF.get_segment(i)
        if segment.section_in_segment(section):
            print("Found section. Offset:",hex(segment['p_vaddr']-segment['p_offset']))
            return segment['p_vaddr']-segment['p_offset']
    return None


def add_functions_to_rela_plt(got_virtual_address_change):
    section = ELF.get_section_by_name(".rela.plt")

    print("GOT address change:",got_virtual_address_change)
    got_new_offset = calculate_new_offset(GOT_INJECT_OFFSET,'.got',ELF_SECTIONS_ALIGNMENT_SIZES)
    sizes = [8,8,8]
    inject_offset = RELA_PLT_INJECT_OFFSET
    assert sum(sizes) * len(symbol_names) == RELA_PLT_INJECT_SIZE, "values not equal"
    for i in range(len(symbol_names)):
        index = get_index_of_symbol_in_dyn_sym(symbol_names[i])
        info = index * 0x100000000 + 0x7
        rela_offset = got_new_offset + got_virtual_address_change
        add_contents_to_file(inject_offset,[rela_offset,info,0x0],sizes)
        #print('added')
        got_new_offset = got_new_offset + GOT_ENTRY_SIZE
        inject_offset+= section['sh_entsize']
    
    num_bytes_to_align = RELA_PLT_ALIGNMENT_SIZE - RELA_PLT_INJECT_SIZE
    if num_bytes_to_align > 0:
        align_section(inject_offset,num_bytes_to_align)

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

def edit_gnu_version_r_section():
    gnu_version_r_section = ELF.get_section_by_name(".gnu.version_r")
    num_versions = gnu_version_r_section.num_versions()
    #print("Num versions", num_versions)
    additional_versions = 1
    cnt_offset = 2

    modify_file(GNU_VERSION_R_OFFSET+cnt_offset,(num_versions+additional_versions).to_bytes(2,'little'))


DYN_SYM_SYMBOL_NAMES = []
## size of got = 8 * (num rela.dyn + num rela.plt)
## size of .plt = 16 * (num rela.plt) + 16

def calculate_new_offset(offset,section,elf_sections_alignment_changes):
    index = ELF_SECTIONS_CHANGES.index(section)
    for i in range(index+1,len(ELF_SECTIONS_CHANGES)):
        offset = offset + elf_sections_alignment_changes[i]
    return offset

def add_functions_to_got():
    sizes = [8]

    plt_sec_new_inject_offset = calculate_new_offset(PLT_SEC_INJECT_OFFSET,'.plt.sec',ELF_SECTIONS_ALIGNMENT_SIZES)
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



def add_functions_to_plt_sec(got_virtual_address_change):
    sizes = [4,3,4,5]
    assert sum(sizes) * len(symbol_names) == PLT_SEC_INJECT_SIZE, "values not equal"
    endbr64 = 0xfa1e0ff3
    jmp = 0x25fff2
    nopl = 0x0000441f0f
    got_new_offset = calculate_new_offset(GOT_INJECT_OFFSET,'.got',ELF_SECTIONS_ALIGNMENT_SIZES)
    plt_sec_new_offset = calculate_new_offset(PLT_SEC_INJECT_OFFSET,'.plt.sec',ELF_SECTIONS_ALIGNMENT_SIZES) + 0xb # 0xb is the distance from the start of the pltsec entry to the rip that is used for calculating relative offset
    inject_offset = PLT_SEC_INJECT_OFFSET
    for i in range(len(symbol_names)):
        jmp_offset = got_new_offset + got_virtual_address_change - plt_sec_new_offset
        add_contents_to_file(inject_offset,[endbr64,jmp,jmp_offset,nopl],sizes)
        inject_offset+= sum(sizes)
        plt_sec_new_offset += sum(sizes)
        got_new_offset = got_new_offset + GOT_ENTRY_SIZE
    num_bytes_to_align = PLT_SEC_ALIGNMENT_SIZE - PLT_SEC_INJECT_SIZE
    if num_bytes_to_align > 0:
        align_section(inject_offset,num_bytes_to_align)


def edit_sections_changes_sizes():
    for i in range(len(ELF_SECTIONS_CHANGES)):
        section_size = ELF.get_section_by_name(ELF_SECTIONS_CHANGES[i])['sh_size']
        total_section_size_offset = SECTION_HEADER_TABLE_OFFSET + SECTION_HEADER_TABLE_ENTRY_SIZE * ELF.get_section_index(ELF_SECTIONS_CHANGES[i]) + SECTION_FILE_OFFSET_STRUCT_OFFSET
        modify_file(total_section_size_offset,(section_size+ELF_SECTIONS_INJECT_SIZES[i]).to_bytes(8,'little'))

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



def get_increased_size_after_section(indices,index,sizes,end_index):
    size = 0
    for j in range(len(indices)):
        if end_index > indices[j]:
            #print("SIZES TO ADD",sizes[j])
            size+=sizes[j]
    return size


def edit_rela_plt_section():
    rela_plt_index = ELF.get_section_index('.rela.plt')
    rela_plt_section = ELF.get_section_by_name(".rela.plt")
    rela_plt_entry_size = rela_plt_section['sh_entsize']
    rela_plt_entry_offset = rela_plt_section['sh_offset']
    got_sec_index = ELF.get_section_index('.got')
    indices = get_indices_of_sections()
    increased_size = get_increased_size_after_section(indices,rela_plt_index,ELF_SECTIONS_ALIGNMENT_SIZES,got_sec_index)
    print("SIZE DIFF RELA PLT:",increased_size)
    for i in range(rela_plt_section.num_relocations()):
        relocation_offset = rela_plt_section.get_relocation(i)['r_offset']
        print("RELOCATION OFFSET",hex(relocation_offset))
        modify_file(rela_plt_entry_offset,(relocation_offset + increased_size).to_bytes(8,'little'))
        rela_plt_entry_offset = rela_plt_entry_offset + rela_plt_entry_size



def calculate_new_offset_of_constant_section(offset,elf_sections_changes,ELF_SECTIONS_ALIGNMENT_SIZES):
    index = get_section_index_of_offset(offset)
    #print(index)
    if index is None:
        return 0
    indices = get_indices_of_sections()
    return get_total_increased_offset(indices,index,ELF_SECTIONS_ALIGNMENT_SIZES)

def edit_entry_point():
    entry_point = ELF['e_entry']
    entry_point_offset = 24
    print("ENTRY POINT:",hex(entry_point))
    new_offset = calculate_new_offset_of_constant_section(entry_point,ELF_SECTIONS_CHANGES,ELF_SECTIONS_ALIGNMENT_SIZES)+entry_point
    print("NEW ENTRY POINT:",hex(new_offset))
    modify_file(entry_point_offset,(new_offset).to_bytes(8,'little'))


FILE_NAME = 'hello'
FILE = open(FILE_NAME,'r+b')
ELF = ELFFile(open(FILE_NAME,'rb'))


def align_offsets():
    aligned_sizes = []
    for i in range(len(ELF_SECTIONS_CHANGES)):
        index = ELF.get_section_index(ELF_SECTIONS_CHANGES[i])
        next_section_index = index + 1
        #xxx4 xxxx8
        size = ELF_SECTIONS_INJECT_SIZES[i]
        section_offset = ELF.get_section(next_section_index)['sh_offset']
        length_to_next_section = size + ELF.get_section_by_name(ELF_SECTIONS_CHANGES[i])['sh_offset']
        #print("Length to next section:",length_to_next_section % 16," | Next section_offset:",section_offset % 16)
        while (length_to_next_section % 16) != (section_offset % 16):
            length_to_next_section = length_to_next_section + 1
            size = size + 1
        #aligned_sizes.append(size)
        aligned_sizes.append(ELF_SECTIONS_INJECT_SIZES[i] + 16 - (ELF_SECTIONS_INJECT_SIZES[i] % 16))
    return aligned_sizes




check_duplicate_symbols_and_versions()
convert_functions_to_str_tab_entry()


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
got_virtual_address_change = calculate_got_virtual_address_change()
#.gnu.version
section = ELF.get_section_by_name(".gnu.version")
GNU_VERSION_INJECT_OFFSET = section['sh_offset'] + section['sh_size']
GNU_VERSION_ENTRY_SIZE = section['sh_entsize']
GNU_VERSION_INJECT_SIZE = len(sym_versions) * GNU_VERSION_ENTRY_SIZE
#.gnu.version_r
section = ELF.get_section_by_name(".gnu.version_r")
GNU_VERSION_R_HEADER_SIZE = 16
GNU_VERSION_R_INJECT_OFFSET = section['sh_offset'] + GNU_VERSION_R_HEADER_SIZE
GNU_VERSION_R_INJECT_SIZE = 16 * len(GLIBC_versions)
NUM_VERSIONS = section.num_versions()
#.symtab
SYM_TAB_SECTION = ELF.get_section_by_name(".symtab")
SYM_TAB_VALUE_STRUCT_OFFSET = 8
NUM_SYMBOLS = SYM_TAB_SECTION.num_symbols()
SYM_TAB_ENTRY_SIZE = 24
if section is not None:
    SYM_TAB_INJECT_OFFSET = SYM_TAB_SECTION['sh_offset'] + SYM_TAB_SECTION['sh_size'] #where the end of symble table is
    SYM_TAB_INJECT_SIZE = len(symbol_names) * SYM_TAB_SECTION['sh_entsize'] #size of functions of add
    SYM_TAB_OFFSET = SYM_TAB_SECTION['sh_offset']
#.rela.plt
section = ELF.get_section_by_name(".rela.plt")
RELA_PLT_INJECT_OFFSET = section['sh_offset'] + section['sh_size']
RELA_PLT_INJECT_SIZE = len(symbol_names) * section['sh_entsize']
#.dynsym
section = ELF.get_section_by_name(".dynsym")
DYN_SYM_INJECT_OFFSET = section['sh_offset'] + section['sh_size']
DYN_SYM_ENTRY_SIZE = section['sh_entsize']
DYN_SYM_INJECT_SIZE = len(symbol_names) * DYN_SYM_ENTRY_SIZE
for i in range(section.num_symbols()):
    DYN_SYM_SYMBOL_NAMES.append(section.get_symbol(i).name)
#.dynstr
section = ELF.get_section_by_name(".dynstr")
DYN_STR_INJECT_OFFSET = section['sh_offset'] + section['sh_size']
DYN_STR_INJECT_SIZE = len(str_tab_entries)


RELA_PLT_OFFSET = ELF.get_section_by_name(".rela.plt")['sh_offset']
DYN_SYM_OFFSET = ELF.get_section_by_name(".dynsym")['sh_offset']
DYN_STR_OFFSET = ELF.get_section_by_name(".dynstr")['sh_offset']
GNU_VERSION_OFFSET = ELF.get_section_by_name(".gnu.version")['sh_offset']
GNU_VERSION_R_OFFSET = ELF.get_section_by_name(".gnu.version_r")['sh_offset']

TEXT_OFFSET = ELF.get_section_by_name(".text")['sh_offset']

SECTIONS_OFFSETS = [SYM_TAB_OFFSET,GOT_OFFSET,PLT_SEC_OFFSET,PLT_OFFSET,RELA_PLT_OFFSET,GNU_VERSION_R_OFFSET,GNU_VERSION_OFFSET,DYN_STR_OFFSET,DYN_SYM_OFFSET]
ELF_SECTIONS_CHANGES = ['.symtab','.got','.plt.sec','.plt','.rela.plt','.gnu.version_r','.gnu.version','.dynstr','.dynsym']
ELF_SECTIONS_INJECT_SIZES = [SYM_TAB_INJECT_SIZE,GOT_INJECT_SIZE,PLT_SEC_INJECT_SIZE,PLT_INJECT_SIZE,RELA_PLT_INJECT_SIZE,GNU_VERSION_R_INJECT_SIZE,GNU_VERSION_INJECT_SIZE,DYN_STR_INJECT_SIZE,DYN_SYM_INJECT_SIZE]
INJECT_OFFSETS = [SYM_TAB_INJECT_OFFSET,GOT_INJECT_OFFSET,PLT_SEC_INJECT_OFFSET,PLT_INJECT_OFFSET,RELA_PLT_INJECT_OFFSET,GNU_VERSION_R_INJECT_OFFSET,GNU_VERSION_INJECT_OFFSET,DYN_STR_INJECT_OFFSET,DYN_SYM_INJECT_OFFSET]
ELF_SECTIONS_ALIGNMENT_SIZES = align_offsets() 

def get_alignment_size(section_name):
    return ELF_SECTIONS_ALIGNMENT_SIZES[ELF_SECTIONS_CHANGES.index(section_name)]

SYM_TAB_ALIGNMENT_SIZE = get_alignment_size('.symtab')
GOT_ALIGNMENT_SIZE = get_alignment_size('.got')
PLT_SEC_ALIGNMENT_SIZE = get_alignment_size('.plt.sec')
PLT_ALIGNMENT_SIZE = get_alignment_size('.plt')
RELA_PLT_ALIGNMENT_SIZE = get_alignment_size('.rela.plt')
GNU_VERSION_R_ALIGNMENT_SIZE = get_alignment_size('.gnu.version_r')
GNU_VERSION_ALIGNMENT_SIZE = get_alignment_size('.gnu.version')
DYN_STR_ALIGNMENT_SIZE = get_alignment_size('.dynstr')
DYN_SYM_ALIGNMENT_SIZE = get_alignment_size('.dynsym')

print("SECTIONS",ELF_SECTIONS_CHANGES)
print("SIZES",ELF_SECTIONS_INJECT_SIZES)
print("ALIGNMENT SIZES",ELF_SECTIONS_ALIGNMENT_SIZES)
print("SECTION OFFSETS",SECTIONS_OFFSETS)
print("INJECT OFFSETS",INJECT_OFFSETS)

edit_entry_point()
edit_symbol_table()
edit_dynamic_section()
edit_rela_dyn_section()
edit_rela_plt_section()
edit_program_header()
edit_gnu_version_r_section()

edit_elf_sections()
edit_sections_changes_sizes()

modify_file(40,(ELF['e_shoff']+sum(ELF_SECTIONS_ALIGNMENT_SIZES)).to_bytes(8,'little'))

print("Num symbols to add ",len(symbol_names))

add_functions_to_sym_tab()
add_functions_to_got()
add_functions_to_plt_sec(got_virtual_address_change)
add_functions_to_plt()
add_functions_to_rela_plt(got_virtual_address_change)
add_versions_to_gnu_version_r()
add_versions_to_gnu_version()
add_strings_to_dyn_str_tab()
add_functions_to_dyn_sym()
