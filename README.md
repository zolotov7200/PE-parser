# pe-dump — парсер Portable Executable (PE32 / PE32+)

Консольная утилита, которая разбирает PE-файл (`.exe`/`.dll`, 32- и 64-битный) и печатает в человекочитаемом виде DOS/NT-заголовки, `OptionalHeader`, таблицу `DataDirectory[16]` и таблицу секций с расшифровкой битовых флагов.

> Доп-проект #95. Реализовано **с нуля**: только бинарное чтение файла в `std::vector<uint8_t>` и собственные определения структур/смещений. **Не используются** DbgHelp, ImageHlp, сторонние PE-библиотеки и `LoadLibrary*` — файл обрабатывается исключительно как массив байт.

---

## Возможности

- Проверка сигнатур `MZ` (`0x5A4D`) и `PE\0\0` (`0x00004550`), переход по `e_lfanew`.
- Разбор `IMAGE_FILE_HEADER`: `Machine` (i386 / AMD64 / ARM64 / ARM / IA64), `NumberOfSections`, `TimeDateStamp` (Unix-time → дата UTC), `SizeOfOptionalHeader`, флаги `Characteristics`.
- Корректная поддержка **PE32** (`Magic = 0x010B`) и **PE32+** (`Magic = 0x020B`): отдельные структуры, ширина `ImageBase` 4/8 байт, наличие/отсутствие `BaseOfData`.
- `OptionalHeader`: `AddressOfEntryPoint`, `ImageBase`, `SectionAlignment`, `FileAlignment`, `SizeOfImage`, `SizeOfHeaders`, `Subsystem` (с расшифровкой), `DllCharacteristics` (ASLR / DEP / CFG и др.), `NumberOfRvaAndSizes`.
- Таблица `DataDirectory[16]` с именами (Export, Import, Resource, …, COM Descriptor) и пометкой, в какую секцию попадает RVA. Индекс 4 (Security) помечается как file offset, а не RVA.
- Таблица секций: `Name[8]` (печатается ровно как 8 байт, без `printf("%s")`), `VirtualSize`, `VirtualAddress`, `SizeOfRawData`, `PointerToRawData`, `Characteristics` (CNT_CODE, MEM_EXECUTE/READ/WRITE и др.), а также заметки про соотношение `SizeOfRawData` и `VirtualSize`.
- Утилита `rvaToFileOffset()` и проверка: печать первых 16 байт по `AddressOfEntryPoint`.
- Проверки границ на каждом чтении: усечённые/битые файлы не приводят к выходу за пределы буфера.

---

## Сборка

Нужен компилятор с поддержкой C++17. Код кроссплатформенный (зависит только от стандартной библиотеки), поэтому собирается и под Windows, и под Linux/macOS.

### MSVC (Visual Studio Build Tools)

```bat
cl /EHsc /W4 /std:c++17 pe-dump.cpp
```

### g++ / clang

```bash
g++ -std=c++17 -Wall -Wextra -O2 -o pe-dump pe-dump.cpp
# или
clang++ -std=c++17 -Wall -Wextra -O2 -o pe-dump pe-dump.cpp
```

---

## Использование

```
pe-dump <file> [--headers-only] [--data-dirs] [--sections-only]
```

| Флаг | Что печатает |
|------|--------------|
| *(без флагов)* | Всё: DOS + File + Optional headers, DataDirectory, секции, байты точки входа |
| `--headers-only` | Только DOS / File / Optional заголовки |
| `--data-dirs` | Только таблицу `DataDirectory[16]` |
| `--sections-only` | Только таблицу секций |

Флаги можно комбинировать (например, `--headers-only --data-dirs`).

### Примеры

```bash
pe-dump notepad.exe
pe-dump kernel32.dll --headers-only
pe-dump app.dll --data-dirs
pe-dump hello64.exe --sections-only
```

### Пример вывода (фрагмент, PE32+)

```
==================== FILE HEADER (IMAGE_FILE_HEADER) ====================
  Machine             : 0x8664  IMAGE_FILE_MACHINE_AMD64 (x64)
  NumberOfSections    : 2
  TimeDateStamp       : 0x5F000000  2020-07-04 04:05:20 UTC
  SizeOfOptionalHeader: 240 (0xF0)
  Characteristics     : 0x0022
      -> EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

==================== OPTIONAL HEADER ====================
  Magic               : 0x020B  (PE32+)
  AddressOfEntryPoint : 0x00001000  (RVA)
  ImageBase           : 0x0000000140000000
  SectionAlignment    : 0x00001000
  FileAlignment       : 0x00000200
  Subsystem           : 3  WINDOWS_CUI (консоль)
  DllCharacteristics  : 0x4140
      -> DYNAMIC_BASE (ASLR) | NX_COMPAT (DEP) | GUARD_CF (CFG)
```

---

## Коды возврата

| Код | Значение |
|-----|----------|
| 0 | Успех |
| 1 | Неверные аргументы командной строки |
| 2 | Не удалось открыть файл |
| 3 | Файл меньше DOS-заголовка |
| 4 | Нет сигнатуры `MZ` (не PE-файл) |
| 5 | `e_lfanew` выходит за пределы файла |
| 6 | Нет сигнатуры `PE\0\0` |
| 7 | Не удалось прочитать `Magic` OptionalHeader |
| 8 | Усечённый OptionalHeader |
| 9 | Неизвестный `Magic` (не PE32 и не PE32+) |

---

## Сверка результата

Рекомендуется сверять вывод с **PE-bear** или **CFF Explorer** на нескольких файлах:

- `hello.exe` (PE32) — соберите `cl hello.c` и без `/DYNAMICBASE`, и с `/DYNAMICBASE` (увидите появление/исчезновение флага `DYNAMIC_BASE`);
- `hello64.exe` (PE32+);
- `notepad.exe`, `kernel32.dll`;
- любая .NET-сборка — у неё заполнен `DataDirectory[14]` (COM Descriptor).

Для побайтового просмотра удобен **HxD**.

---

## Структура заголовков (кратко)

```
+--------------------+  offset 0
| IMAGE_DOS_HEADER   |  64 байта, e_magic='MZ', e_lfanew -> PE
+--------------------+
| DOS stub           |  "This program cannot be run in DOS mode"
+--------------------+  offset = e_lfanew
| "PE\0\0"           |  4 байта, сигнатура
| IMAGE_FILE_HEADER  |  20 байт
| IMAGE_OPTIONAL_HDR |  PE32: 0x010B / PE32+: 0x020B, + DataDirectory[16]
+--------------------+  offset = e_lfanew + 4 + 20 + SizeOfOptionalHeader
| Section headers    |  NumberOfSections * 40 байт
+--------------------+
| Секции (.text,     |  сырые данные по PointerToRawData
|  .rdata, .data...) |
+--------------------+
```

**RVA → file offset:** если `rva < SizeOfHeaders`, то `offset = rva`; иначе найти секцию, где `VirtualAddress ≤ rva < VirtualAddress + max(VirtualSize, SizeOfRawData)`, и вернуть `PointerToRawData + (rva − VirtualAddress)`.

---

## Ограничения

- Утилита разбирает **заголовки и таблицу секций**. Глубокий разбор таблиц импорта/экспорта/релокаций не входит в задание (теория по ним приведена в методичке).
- Поле `Magic` определяет разрядность; на значение `Machine` для выбора структуры не опираемся.
- Для упакованных файлов (например, UPX) заголовки могут выглядеть нестандартно — это ожидаемо.

---

## Этическое замечание

Проект предназначен только для собственных `.exe`/`.dll` и открытых системных библиотек (`notepad.exe`, `kernel32.dll`). Анализ и модификация чужого закрытого ПО без разрешения правообладателя запрещены. Цель — образовательная: понять формат исполняемых файлов и работу системного загрузчика.

---

## Файлы проекта

- `pe-dump.cpp` — исходный код утилиты (один файл).
- `make_test_pe.py` — генератор тестовых PE32 / PE32+ файлов для проверки парсера.
- `README.md` — этот файл.
