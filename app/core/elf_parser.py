from elftools.elf.elffile import ELFFile
from io import BytesIO

def enrich(report, file_bytes: bytes):
    stream = BytesIO(file_bytes)
    elf = ELFFile(stream)

    report.metadata = {
        "arch": elf["e_machine"],
        "entry_point": hex(elf["e_entry"]),
        "bits": elf.elfclass,
        "endianness": "little" if elf.little_endian else "big",
    }

    for section in elf.iter_sections():
        report.sections.append({
            "name": section.name,
            "size": section["sh_size"],
            "addr": hex(section["sh_addr"])
        })
    
    return report

def extract_text_selection(file_bytes):
    stream = BytesIO(file_bytes)
    elf = ELFFile(stream)

    text_section = elf.get_section_by_name(".text")

    if not text_section:
        raise ValueError("No .text section found")
    
    return {
        "bytes": text_section.data(),
        "addr": text_section["sh_addr"],
        "size": text_section["sh_size"],
        "bits": elf.elfclass
    }