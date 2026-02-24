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