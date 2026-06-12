// pe-dump — консольный парсер Portable Executable (PE32 / PE32+)
//
// Доп-проект #95: DOS/NT-заголовки, OptionalHeader, DataDirectory[16],
// таблица секций, RVA->file offset.
//
// Принцип: НИКАКИХ DbgHelp / ImageHlp / сторонних PE-библиотек и НИКАКОГО
// LoadLibrary. Файл читается целиком в std::vector<uint8_t> и разбирается
// вручную по собственным определениям структур и смещениям.
//
// Сборка (MSVC):   cl /EHsc /W4 /std:c++17 pe-dump.cpp
// Сборка (g++):    g++ -std=c++17 -Wall -Wextra -O2 -o pe-dump pe-dump.cpp
//
// Использование:   pe-dump <file> [--headers-only] [--data-dirs] [--sections-only]
//
// Код кроссплатформенный: используются только <cstdint>, <vector>, <cstdio> и т.п.,
// поэтому утилита собирается и под Windows (MSVC/MinGW), и под Linux (g++/clang).

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>

// ---------------------------------------------------------------------------
// Собственные определения структур PE.
// #pragma pack(1) убирает выравнивание компилятора: раскладка байт в памяти
// должна 1-в-1 совпадать с раскладкой в файле, иначе memcpy «поедет».
// ---------------------------------------------------------------------------
#pragma pack(push, 1)

struct DosHeader {            // IMAGE_DOS_HEADER — ровно 64 байта
    uint16_t e_magic;         // 'MZ' = 0x5A4D
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;        // file offset до сигнатуры "PE\0\0"
};

struct FileHeader {           // IMAGE_FILE_HEADER (COFF) — 20 байт
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct DataDirectory {        // IMAGE_DATA_DIRECTORY — 8 байт
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct OptionalHeader32 {     // IMAGE_OPTIONAL_HEADER32 (Magic = 0x010B)
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;          // <-- есть только в PE32
    uint32_t ImageBase;           // 4 байта
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    // DataDirectory[NumberOfRvaAndSizes] читается отдельно
};

struct OptionalHeader64 {     // IMAGE_OPTIONAL_HEADER64 (Magic = 0x020B)
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    // НЕТ BaseOfData в PE32+
    uint64_t ImageBase;           // 8 байт
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;  // указательные поля — по 8 байт
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
};

struct SectionHeader {        // IMAGE_SECTION_HEADER — 40 байт
    uint8_t  Name[8];             // ASCII, не обязательно null-terminated!
    uint32_t VirtualSize;         // union с PhysicalAddress
    uint32_t VirtualAddress;      // RVA
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;    // file offset
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

#pragma pack(pop)

// Контрольные размеры структур (фиксируем на этапе компиляции).
static_assert(sizeof(DosHeader) == 64,       "DosHeader must be 64 bytes");
static_assert(sizeof(FileHeader) == 20,      "FileHeader must be 20 bytes");
static_assert(sizeof(DataDirectory) == 8,    "DataDirectory must be 8 bytes");
static_assert(sizeof(OptionalHeader32) == 96,"OptionalHeader32 must be 96 bytes");
static_assert(sizeof(OptionalHeader64) == 112,"OptionalHeader64 must be 112 bytes");
static_assert(sizeof(SectionHeader) == 40,   "SectionHeader must be 40 bytes");

// ---------------------------------------------------------------------------
// Константы
// ---------------------------------------------------------------------------
static const uint16_t DOS_MAGIC      = 0x5A4D;     // 'MZ'
static const uint32_t PE_SIGNATURE   = 0x00004550; // 'PE\0\0'
static const uint16_t MAGIC_PE32     = 0x010B;
static const uint16_t MAGIC_PE32PLUS = 0x020B;
static const int      NUM_DIRS       = 16;

static const char* kDirNames[NUM_DIRS] = {
    "Export", "Import", "Resource", "Exception",
    "Security", "BaseRelocation", "Debug", "Architecture",
    "GlobalPtr", "TLS", "LoadConfig", "BoundImport",
    "IAT", "DelayImport", "COM Descriptor", "Reserved"
};

// ---------------------------------------------------------------------------
// Безопасное чтение из буфера (little-endian).
// Так как все целевые платформы (x86/x64/ARM little-endian) хранят числа в LE,
// memcpy упакованной структуры даёт корректные значения. Для надёжности и
// проверки границ читаем через эти помощники.
// ---------------------------------------------------------------------------
struct Reader {
    const std::vector<uint8_t>& buf;
    explicit Reader(const std::vector<uint8_t>& b) : buf(b) {}

    bool inRange(size_t off, size_t len) const {
        return off <= buf.size() && len <= buf.size() - off;
    }

    // Скопировать POD-структуру по смещению с проверкой границ.
    template <typename T>
    bool read(size_t off, T& out) const {
        if (!inRange(off, sizeof(T))) return false;
        std::memcpy(&out, buf.data() + off, sizeof(T));
        return true;
    }

    bool readU16(size_t off, uint16_t& v) const { return read(off, v); }
    bool readU32(size_t off, uint32_t& v) const { return read(off, v); }
};

// ---------------------------------------------------------------------------
// Помощники форматирования флагов
// ---------------------------------------------------------------------------
struct FlagDef { uint32_t mask; const char* name; };

static std::string decodeFlags(uint32_t value, const FlagDef* defs, size_t n) {
    std::string out;
    for (size_t i = 0; i < n; ++i) {
        if (value & defs[i].mask) {
            if (!out.empty()) out += " | ";
            out += defs[i].name;
        }
    }
    if (out.empty()) out = "(none)";
    return out;
}

static const char* machineName(uint16_t m) {
    switch (m) {
        case 0x014C: return "IMAGE_FILE_MACHINE_I386 (x86)";
        case 0x8664: return "IMAGE_FILE_MACHINE_AMD64 (x64)";
        case 0xAA64: return "IMAGE_FILE_MACHINE_ARM64";
        case 0x01C0: return "IMAGE_FILE_MACHINE_ARM";
        case 0x01C4: return "IMAGE_FILE_MACHINE_ARMNT (Thumb-2)";
        case 0x0200: return "IMAGE_FILE_MACHINE_IA64";
        case 0x0000: return "IMAGE_FILE_MACHINE_UNKNOWN";
        default:     return "<unknown machine>";
    }
}

static const char* subsystemName(uint16_t s) {
    switch (s) {
        case 0:  return "UNKNOWN";
        case 1:  return "NATIVE (драйвер / нет подсистемы)";
        case 2:  return "WINDOWS_GUI";
        case 3:  return "WINDOWS_CUI (консоль)";
        case 5:  return "OS2_CUI";
        case 7:  return "POSIX_CUI";
        case 8:  return "NATIVE_WINDOWS";
        case 9:  return "WINDOWS_CE_GUI";
        case 10: return "EFI_APPLICATION";
        case 11: return "EFI_BOOT_SERVICE_DRIVER";
        case 12: return "EFI_RUNTIME_DRIVER";
        case 13: return "EFI_ROM";
        case 14: return "XBOX";
        case 16: return "WINDOWS_BOOT_APPLICATION";
        default: return "<unknown subsystem>";
    }
}

static const FlagDef kFileChars[] = {
    {0x0001, "RELOCS_STRIPPED"},
    {0x0002, "EXECUTABLE_IMAGE"},
    {0x0004, "LINE_NUMS_STRIPPED"},
    {0x0008, "LOCAL_SYMS_STRIPPED"},
    {0x0010, "AGGRESSIVE_WS_TRIM"},
    {0x0020, "LARGE_ADDRESS_AWARE"},
    {0x0080, "BYTES_REVERSED_LO"},
    {0x0100, "32BIT_MACHINE"},
    {0x0200, "DEBUG_STRIPPED"},
    {0x0400, "REMOVABLE_RUN_FROM_SWAP"},
    {0x0800, "NET_RUN_FROM_SWAP"},
    {0x1000, "SYSTEM"},
    {0x2000, "DLL"},
    {0x4000, "UP_SYSTEM_ONLY"},
    {0x8000, "BYTES_REVERSED_HI"},
};

static const FlagDef kDllChars[] = {
    {0x0020, "HIGH_ENTROPY_VA (64-bit ASLR)"},
    {0x0040, "DYNAMIC_BASE (ASLR)"},
    {0x0080, "FORCE_INTEGRITY"},
    {0x0100, "NX_COMPAT (DEP)"},
    {0x0200, "NO_ISOLATION"},
    {0x0400, "NO_SEH"},
    {0x0800, "NO_BIND"},
    {0x1000, "APPCONTAINER"},
    {0x2000, "WDM_DRIVER"},
    {0x4000, "GUARD_CF (CFG)"},
    {0x8000, "TERMINAL_SERVER_AWARE"},
};

static const FlagDef kSecChars[] = {
    {0x00000008, "TYPE_NO_PAD"},
    {0x00000020, "CNT_CODE"},
    {0x00000040, "CNT_INITIALIZED_DATA"},
    {0x00000080, "CNT_UNINITIALIZED_DATA (BSS)"},
    {0x00000200, "LNK_INFO"},
    {0x00000800, "LNK_REMOVE"},
    {0x00001000, "LNK_COMDAT"},
    {0x00008000, "GPREL"},
    {0x01000000, "LNK_NRELOC_OVFL"},
    {0x02000000, "MEM_DISCARDABLE"},
    {0x04000000, "MEM_NOT_CACHED"},
    {0x08000000, "MEM_NOT_PAGED"},
    {0x10000000, "MEM_SHARED"},
    {0x20000000, "MEM_EXECUTE"},
    {0x40000000, "MEM_READ"},
    {0x80000000, "MEM_WRITE"},
};

// Декодирование выравнивания секции (биты 20..23 поля Characteristics).
static std::string sectionAlign(uint32_t ch) {
    uint32_t a = (ch & 0x00F00000u) >> 20;
    if (a == 0) return "";
    unsigned bytes = 1u << (a - 1);
    char b[32];
    std::snprintf(b, sizeof(b), " | ALIGN_%uBYTES", bytes);
    return b;
}

// ---------------------------------------------------------------------------
// Глобальное представление разобранного PE (для RVA->offset)
// ---------------------------------------------------------------------------
struct ParsedPE {
    bool     is64 = false;
    uint32_t sizeOfHeaders = 0;
    uint32_t entryPoint = 0;
    std::vector<SectionHeader> sections;
};

// Этап 5. RVA -> file offset.
// Возвращает true и offset, либо false если RVA не отображается.
static bool rvaToFileOffset(const ParsedPE& pe, uint32_t rva, uint32_t& fileOff) {
    // RVA внутри заголовков (DOS+NT+таблица секций) совпадает с file offset.
    if (rva < pe.sizeOfHeaders) { fileOff = rva; return true; }
    for (const auto& s : pe.sections) {
        uint32_t vsize = s.VirtualSize > s.SizeOfRawData ? s.VirtualSize : s.SizeOfRawData;
        if (vsize == 0) vsize = s.SizeOfRawData;
        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + vsize) {
            // У секции без сырых данных (чистый BSS) отображения в файле нет.
            if (s.SizeOfRawData == 0) return false;
            fileOff = s.PointerToRawData + (rva - s.VirtualAddress);
            return true;
        }
    }
    return false; // не попало ни в одну секцию
}

// В какую секцию (по имени) попадает данный RVA — для пометки DataDirectory.
static std::string sectionOfRva(const ParsedPE& pe, uint32_t rva) {
    if (rva == 0) return "-";
    if (rva < pe.sizeOfHeaders) return "(headers)";
    for (const auto& s : pe.sections) {
        uint32_t vsize = s.VirtualSize > s.SizeOfRawData ? s.VirtualSize : s.SizeOfRawData;
        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + vsize) {
            char name[9]; std::memcpy(name, s.Name, 8); name[8] = '\0';
            return std::string(name);
        }
    }
    return "<not mapped>";
}

// ---------------------------------------------------------------------------
// Вывод
// ---------------------------------------------------------------------------
static void banner(const char* title) {
    std::printf("\n==================== %s ====================\n", title);
}

static std::string timeStr(uint32_t t) {
    // TimeDateStamp — Unix time (секунды с 1970-01-01 UTC).
    std::time_t tt = static_cast<std::time_t>(t);
    std::tm tmv{};
#if defined(_WIN32)
    gmtime_s(&tmv, &tt);
#else
    gmtime_r(&tt, &tmv);
#endif
    char b[64];
    std::strftime(b, sizeof(b), "%Y-%m-%d %H:%M:%S UTC", &tmv);
    return b;
}

static void dumpDos(const DosHeader& dos) {
    banner("DOS HEADER (IMAGE_DOS_HEADER)");
    std::printf("  e_magic   : 0x%04X (%c%c)\n", dos.e_magic,
                (dos.e_magic & 0xFF), (dos.e_magic >> 8) & 0xFF);
    std::printf("  e_lfanew  : 0x%08X  (file offset до сигнатуры PE)\n",
                (uint32_t)dos.e_lfanew);
}

static void dumpFileHeader(const FileHeader& fh) {
    banner("FILE HEADER (IMAGE_FILE_HEADER)");
    std::printf("  Machine             : 0x%04X  %s\n", fh.Machine, machineName(fh.Machine));
    std::printf("  NumberOfSections    : %u\n", fh.NumberOfSections);
    std::printf("  TimeDateStamp       : 0x%08X  %s\n", fh.TimeDateStamp, timeStr(fh.TimeDateStamp).c_str());
    std::printf("  SizeOfOptionalHeader: %u (0x%X)\n", fh.SizeOfOptionalHeader, fh.SizeOfOptionalHeader);
    std::printf("  Characteristics     : 0x%04X\n", fh.Characteristics);
    std::printf("      -> %s\n", decodeFlags(fh.Characteristics, kFileChars,
                                              sizeof(kFileChars)/sizeof(kFileChars[0])).c_str());
}

// Общая печать полей OptionalHeader (значения уже извлечены в широкие типы).
static void printOptionalCommon(
        const char* kind, uint16_t magic,
        uint8_t majLink, uint8_t minLink,
        uint32_t sizeOfCode, uint32_t sizeOfInit,
        uint32_t aoep, uint32_t baseOfCode,
        uint64_t imageBase, uint32_t secAlign, uint32_t fileAlign,
        uint32_t sizeOfImage, uint32_t sizeOfHeaders,
        uint16_t subsystem, uint16_t dllChars, uint32_t numRva) {
    banner("OPTIONAL HEADER");
    std::printf("  Magic               : 0x%04X  (%s)\n", magic, kind);
    std::printf("  LinkerVersion       : %u.%u\n", majLink, minLink);
    std::printf("  SizeOfCode          : 0x%08X\n", sizeOfCode);
    std::printf("  SizeOfInitData      : 0x%08X\n", sizeOfInit);
    std::printf("  AddressOfEntryPoint : 0x%08X  (RVA)\n", aoep);
    std::printf("  BaseOfCode          : 0x%08X  (RVA)\n", baseOfCode);
    std::printf("  ImageBase           : 0x%016llX\n", (unsigned long long)imageBase);
    std::printf("  SectionAlignment    : 0x%08X\n", secAlign);
    std::printf("  FileAlignment       : 0x%08X\n", fileAlign);
    std::printf("  SizeOfImage         : 0x%08X  (выровнен по SectionAlignment)\n", sizeOfImage);
    std::printf("  SizeOfHeaders       : 0x%08X  (выровнен по FileAlignment)\n", sizeOfHeaders);
    std::printf("  Subsystem           : %u  %s\n", subsystem, subsystemName(subsystem));
    std::printf("  DllCharacteristics  : 0x%04X\n", dllChars);
    std::printf("      -> %s\n", decodeFlags(dllChars, kDllChars,
                                              sizeof(kDllChars)/sizeof(kDllChars[0])).c_str());
    std::printf("  NumberOfRvaAndSizes : %u\n", numRva);
}

static void dumpDataDirs(const ParsedPE& pe, const std::vector<DataDirectory>& dirs) {
    banner("DATA DIRECTORIES (IMAGE_DATA_DIRECTORY[16])");
    std::printf("  Idx  %-16s %-12s %-12s %s\n", "Name", "RVA", "Size", "Section");
    for (size_t i = 0; i < dirs.size(); ++i) {
        const char* nm = (i < NUM_DIRS) ? kDirNames[i] : "?";
        // Индекс 4 (Security/Certificate) хранит FILE OFFSET, а не RVA.
        std::string sect = (i == 4) ? "(file offset)" : sectionOfRva(pe, dirs[i].VirtualAddress);
        std::printf("  [%2zu] %-16s 0x%08X   0x%08X   %s\n",
                    i, nm, dirs[i].VirtualAddress, dirs[i].Size, sect.c_str());
    }
}

static void dumpSections(const ParsedPE& pe) {
    banner("SECTION TABLE (IMAGE_SECTION_HEADER[])");
    for (size_t i = 0; i < pe.sections.size(); ++i) {
        const SectionHeader& s = pe.sections[i];
        // Name[8] — НЕ обязательно null-terminated: копируем максимум 8 байт.
        char name[9]; std::memcpy(name, s.Name, 8); name[8] = '\0';
        std::printf("\n  [%zu] %-8s\n", i, name);
        std::printf("      VirtualSize     : 0x%08X (%u)\n", s.VirtualSize, s.VirtualSize);
        std::printf("      VirtualAddress  : 0x%08X (RVA)\n", s.VirtualAddress);
        std::printf("      SizeOfRawData   : 0x%08X (%u)\n", s.SizeOfRawData, s.SizeOfRawData);
        std::printf("      PointerToRawData: 0x%08X (file offset)\n", s.PointerToRawData);
        std::printf("      Characteristics : 0x%08X\n", s.Characteristics);
        std::printf("          -> %s%s\n",
                    decodeFlags(s.Characteristics, kSecChars,
                                sizeof(kSecChars)/sizeof(kSecChars[0])).c_str(),
                    sectionAlign(s.Characteristics).c_str());
        if (s.SizeOfRawData > s.VirtualSize)
            std::printf("          note: SizeOfRawData > VirtualSize -> хвост = zero-padding на диске\n");
        else if (s.VirtualSize > s.SizeOfRawData)
            std::printf("          note: VirtualSize > SizeOfRawData -> разница зануляется в памяти (BSS-хвост)\n");
    }
}

// Печать первых 16 байт по entry point (проверка RVA->offset, этап 5).
static void dumpEntryBytes(const ParsedPE& pe, const std::vector<uint8_t>& buf) {
    banner("ENTRY POINT (проверка RVA -> file offset)");
    uint32_t off = 0;
    if (!rvaToFileOffset(pe, pe.entryPoint, off)) {
        std::printf("  AddressOfEntryPoint = 0x%08X -> RVA не отображается в файл\n", pe.entryPoint);
        return;
    }
    std::printf("  AddressOfEntryPoint = 0x%08X -> file offset 0x%08X\n", pe.entryPoint, off);
    std::printf("  Первые 16 байт: ");
    for (int i = 0; i < 16; ++i) {
        if (off + (uint32_t)i < buf.size())
            std::printf("%02X ", buf[off + i]);
    }
    std::printf("\n");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
static void usage(const char* prog) {
    std::fprintf(stderr,
        "Usage: %s <file> [--headers-only] [--data-dirs] [--sections-only]\n", prog);
}

int main(int argc, char** argv) {
    system("chcp 65001 > nul");
    if (argc < 2) { usage(argv[0]); return 1; }

    std::string path;
    bool headersOnly = false, dataDirsOnly = false, sectionsOnly = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--headers-only")  headersOnly = true;
        else if (a == "--data-dirs")     dataDirsOnly = true;
        else if (a == "--sections-only") sectionsOnly = true;
        else if (!a.empty() && a[0] == '-') { usage(argv[0]); return 1; }
        else path = a;
    }
    if (path.empty()) { usage(argv[0]); return 1; }

    // Какие блоки печатать. Без флагов — всё.
    bool noFlags = !headersOnly && !dataDirsOnly && !sectionsOnly;
    bool showHeaders  = noFlags || headersOnly;
    bool showDirs     = noFlags || dataDirsOnly;
    bool showSections = noFlags || sectionsOnly;
    bool showEntry    = noFlags;

    // --- Этап 1: чтение файла целиком в std::vector<uint8_t> ---
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::fprintf(stderr, "Error: не удалось открыть '%s'\n", path.c_str()); return 2; }
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());
    if (buf.size() < sizeof(DosHeader)) {
        std::fprintf(stderr, "Error: файл слишком мал для DOS-заголовка\n"); return 3;
    }
    Reader rd(buf);
    std::printf("File: %s  (%zu bytes)\n", path.c_str(), buf.size());

    // --- DOS-заголовок ---
    DosHeader dos{};
    rd.read(0, dos);
    if (dos.e_magic != DOS_MAGIC) {
        std::fprintf(stderr, "Error: не PE-файл (нет сигнатуры 'MZ')\n"); return 4;
    }
    uint32_t lfanew = (uint32_t)dos.e_lfanew;

    // Проверка: e_lfanew + минимальный NT-заголовок помещается в файл.
    if (!rd.inRange(lfanew, 4 + sizeof(FileHeader))) {
        std::fprintf(stderr, "Error: e_lfanew выходит за пределы файла\n"); return 5;
    }

    // --- Сигнатура PE ---
    uint32_t peSig = 0;
    rd.readU32(lfanew, peSig);
    if (peSig != PE_SIGNATURE) {
        std::fprintf(stderr, "Error: нет сигнатуры PE (0x00004550)\n"); return 6;
    }

    // --- FILE HEADER ---
    FileHeader fh{};
    rd.read(lfanew + 4, fh);

    // --- OPTIONAL HEADER: сначала Magic ---
    size_t optOff = (size_t)lfanew + 4 + sizeof(FileHeader);
    uint16_t magic = 0;
    if (!rd.readU16(optOff, magic)) {
        std::fprintf(stderr, "Error: не удалось прочитать Magic OptionalHeader\n"); return 7;
    }

    ParsedPE pe;
    std::vector<DataDirectory> dirs;
    uint32_t numRva = 0;
    size_t dirOff = 0;

    if (magic == MAGIC_PE32) {
        pe.is64 = false;
        OptionalHeader32 oh{};
        if (!rd.read(optOff, oh)) { std::fprintf(stderr, "Error: усечённый OptionalHeader32\n"); return 8; }
        pe.sizeOfHeaders = oh.SizeOfHeaders;
        pe.entryPoint = oh.AddressOfEntryPoint;
        numRva = oh.NumberOfRvaAndSizes;
        dirOff = optOff + sizeof(OptionalHeader32);

        if (showHeaders) {
            dumpDos(dos);
            dumpFileHeader(fh);
            printOptionalCommon("PE32", oh.Magic, oh.MajorLinkerVersion, oh.MinorLinkerVersion,
                                oh.SizeOfCode, oh.SizeOfInitializedData, oh.AddressOfEntryPoint,
                                oh.BaseOfCode, (uint64_t)oh.ImageBase, oh.SectionAlignment,
                                oh.FileAlignment, oh.SizeOfImage, oh.SizeOfHeaders,
                                oh.Subsystem, oh.DllCharacteristics, oh.NumberOfRvaAndSizes);
            std::printf("  BaseOfData          : 0x%08X  (только в PE32)\n", oh.BaseOfData);
        }
    } else if (magic == MAGIC_PE32PLUS) {
        pe.is64 = true;
        OptionalHeader64 oh{};
        if (!rd.read(optOff, oh)) { std::fprintf(stderr, "Error: усечённый OptionalHeader64\n"); return 8; }
        pe.sizeOfHeaders = oh.SizeOfHeaders;
        pe.entryPoint = oh.AddressOfEntryPoint;
        numRva = oh.NumberOfRvaAndSizes;
        dirOff = optOff + sizeof(OptionalHeader64);

        if (showHeaders) {
            dumpDos(dos);
            dumpFileHeader(fh);
            printOptionalCommon("PE32+", oh.Magic, oh.MajorLinkerVersion, oh.MinorLinkerVersion,
                                oh.SizeOfCode, oh.SizeOfInitializedData, oh.AddressOfEntryPoint,
                                oh.BaseOfCode, oh.ImageBase, oh.SectionAlignment,
                                oh.FileAlignment, oh.SizeOfImage, oh.SizeOfHeaders,
                                oh.Subsystem, oh.DllCharacteristics, oh.NumberOfRvaAndSizes);
            std::printf("  (BaseOfData отсутствует в PE32+)\n");
        }
    } else {
        std::fprintf(stderr, "Error: неизвестный Magic OptionalHeader: 0x%04X\n", magic);
        return 9;
    }

    // --- DataDirectory[NumberOfRvaAndSizes], но не больше 16 для печати ---
    uint32_t dirsToRead = numRva;
    if (dirsToRead > 64) dirsToRead = 64; // защита от мусора
    for (uint32_t i = 0; i < dirsToRead; ++i) {
        DataDirectory dd{};
        if (!rd.read(dirOff + i * sizeof(DataDirectory), dd)) break;
        dirs.push_back(dd);
    }
    // Для печати ограничиваемся 16 каноническими записями.
    if (dirs.size() > NUM_DIRS) dirs.resize(NUM_DIRS);

    // --- Таблица секций ---
    // Адрес: e_lfanew + 4 + sizeof(FileHeader) + SizeOfOptionalHeader
    size_t secOff = (size_t)lfanew + 4 + sizeof(FileHeader) + fh.SizeOfOptionalHeader;
    for (uint16_t i = 0; i < fh.NumberOfSections; ++i) {
        SectionHeader s{};
        if (!rd.read(secOff + (size_t)i * sizeof(SectionHeader), s)) {
            std::fprintf(stderr, "Warning: таблица секций усечена на записи %u\n", i);
            break;
        }
        pe.sections.push_back(s);
    }

    // --- Вывод по флагам ---
    if (showDirs)     dumpDataDirs(pe, dirs);
    if (showSections) dumpSections(pe);
    if (showEntry)    dumpEntryBytes(pe, buf);

    return 0;
}
