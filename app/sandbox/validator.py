MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB


def validate_elf(file_bytes: bytes):
    if len(file_bytes) > MAX_FILE_SIZE:
        raise ValueError("File too large")

    # Check for ELF magic number (0x7F 'E' 'L' 'F')
    if not (file_bytes[0] == 0x7F and file_bytes[1:4] == b'ELF'):
        raise ValueError("Not a valid ELF file")