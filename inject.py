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

# Example usage
elf_file_path = "hello"  # Replace with the path to your ELF file

# Read the ELF file as bytes
elf_bytes = read_elf_file(elf_file_path)
# Specify the offset as a numerical value (0x4040)
offset_to_insert = 0x1194
bytes_to_insert = bytes([0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x83, 0x45, 0xfc, 0x01])  # Add multiple bytes
modified_elf_bytes = insert_bytes_in_elf(elf_bytes, offset_to_insert, bytes_to_insert)

# Write the modified ELF bytes back to the file
write_elf_file(modified_elf_bytes, "hello")
