#!/usr/bin/env python3
# Генератор минимальных, но структурно валидных PE-файлов для проверки pe-dump.
# Собирает PE32 и PE32+ вручную из байт. Не исполняемые — только для парсинга.
import struct

def build(is64, fname):
    FILE_ALIGN = 0x200
    SECT_ALIGN = 0x1000

    # --- DOS header (64 байта) + DOS stub ---
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, e_lfanew)
    dos[0x40:0x4E] = b'This is a stub'  # просто заполнитель

    # --- сигнатура PE ---
    pe_sig = b'PE\x00\x00'

    # --- FILE HEADER (20 байт) ---
    machine = 0x8664 if is64 else 0x014C
    num_sections = 2
    timestamp = 0x5F000000
    opt_size = 0xF0 if is64 else 0xE0
    chars = 0x0002 | 0x0020 if is64 else 0x0002 | 0x0100  # EXEC + (LAA|32BIT)
    file_hdr = struct.pack('<HHIIIHH', machine, num_sections, timestamp, 0, 0, opt_size, chars)

    magic = 0x020B if is64 else 0x010B
    aoep = 0x1000
    base_of_code = 0x1000
    image_base = 0x140000000 if is64 else 0x00400000
    size_of_headers = FILE_ALIGN
    # 2 секции по 0x1000 виртуально, плюс заголовки
    size_of_image = 0x1000 + 0x1000 * num_sections
    subsystem = 3  # CUI
    dll_chars = 0x0040 | 0x0100 | 0x4000  # ASLR | DEP | CFG
    num_rva = 16

    if not is64:
        opt = struct.pack('<HBBIIIIII',
            magic, 14, 0, 0x200, 0x200, 0, aoep, base_of_code, 0x2000)  # +BaseOfData
        opt += struct.pack('<I', image_base)
        opt += struct.pack('<II', SECT_ALIGN, FILE_ALIGN)
        opt += struct.pack('<HHHHHH', 6,0, 0,0, 6,0)
        opt += struct.pack('<III', 0, size_of_image, size_of_headers)
        opt += struct.pack('<I', 0)  # checksum
        opt += struct.pack('<HH', subsystem, dll_chars)
        opt += struct.pack('<IIII', 0x100000, 0x1000, 0x100000, 0x1000)  # stack/heap 4-байтные
        opt += struct.pack('<II', 0, num_rva)
    else:
        opt = struct.pack('<HBBIIIII',
            magic, 14, 0, 0x200, 0x200, 0, aoep, base_of_code)  # нет BaseOfData
        opt += struct.pack('<Q', image_base)
        opt += struct.pack('<II', SECT_ALIGN, FILE_ALIGN)
        opt += struct.pack('<HHHHHH', 6,0, 0,0, 6,0)
        opt += struct.pack('<III', 0, size_of_image, size_of_headers)
        opt += struct.pack('<I', 0)
        opt += struct.pack('<HH', subsystem, dll_chars)
        opt += struct.pack('<QQQQ', 0x100000, 0x1000, 0x100000, 0x1000)  # stack/heap 8-байтные
        opt += struct.pack('<II', 0, num_rva)

    # --- DataDirectory[16] ---
    dirs = bytearray(16 * 8)
    # Имитируем Import dir (idx 1) в .rdata и IAT (idx 12)
    struct.pack_into('<II', dirs, 1*8, 0x2000, 0x50)   # Import -> RVA 0x2000
    struct.pack_into('<II', dirs, 12*8, 0x2050, 0x20)  # IAT

    opt += bytes(dirs)
    assert len(opt) == opt_size, (len(opt), opt_size)

    # --- Таблица секций (40 байт каждая) ---
    def section(name, vsize, vaddr, rawsize, rawptr, chars):
        n = name.encode() + b'\x00' * (8 - len(name))
        return n + struct.pack('<IIIIIIHHI', vsize, vaddr, rawsize, rawptr, 0,0,0,0, chars)

    sec_text = section('.text', 0x100, 0x1000, 0x200, 0x200,
                       0x20 | 0x20000000 | 0x40000000)  # CNT_CODE|EXECUTE|READ
    sec_rdata = section('.rdata', 0x80, 0x2000, 0x200, 0x400,
                        0x40 | 0x40000000)  # INIT_DATA|READ

    headers = bytes(dos) + pe_sig + file_hdr + opt + sec_text + sec_rdata
    assert len(headers) <= size_of_headers
    headers += b'\x00' * (size_of_headers - len(headers))

    # --- Сырые данные секций ---
    text = b'\x90' * 16 + b'\xCC' * (0x200 - 16)  # точка входа: NOP-ы
    rdata = b'\x00' * 0x200

    data = headers + text + rdata
    with open(fname, 'wb') as f:
        f.write(data)
    print(f'wrote {fname}: {len(data)} bytes, {"PE32+" if is64 else "PE32"}')

build(False, 'hello32.exe')
build(True, 'hello64.exe')
