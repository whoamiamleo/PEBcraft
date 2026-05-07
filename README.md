# PEBcraft

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white)
![Visual Studio](https://img.shields.io/badge/Visual%20Studio-2019%2B-5C2D91?style=flat-square&logo=visualstudio&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?style=flat-square)
![Authorized Pentesting Only](https://img.shields.io/badge/⚠%EF%B8%8F%20Authorized%20Pentesting%20Only-critical?style=flat-square)

Transforms C source code into position-independent shellcode by resolving Windows APIs via the Process Environment Block (PEB), bypassing the Import Address Table entirely.

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
  - [Examples](#examples)
  - [Warnings](#warnings)
- [Support](#support)
- [Formatting](#formatting)
  - [Input](#input)
  - [Output](#output)
- [Contributing](#contributing)
- [Attribution](#attribution)
- [Legal & Ethics](#legal--ethics)
- [License](#license)

---

## Features

- **Dynamic PEB resolution**: Resolves Windows API functions directly via the Process Environment Block, bypassing the Import Address Table to minimize forensic footprint.
- **Multi-architecture**: Generates position-independent x86 and x64 assembly directly from C source.
- **API obfuscation**: Employs bit-mixed hashing for module and function names to defeat both static and dynamic string analysis tools.
- **Encrypted string literals**: Implements compile-time string encryption with stack-based runtime decryption to prevent plaintext strings from appearing in the binary.
- **Streamlined development**: Simplifies the creation of sophisticated, weaponized payloads for offensive security research and red team operations.

## How It Works

```
C Source  (PEB API resolution macros, XOR() string encryption)
    │
    ▼
[Visual Studio Build]   ← x64 or x86 Release, /GS- disabled
    │
    ▼
PEBcraft.exe            ← position-independent, no IAT imports
    │
    ▼
[PEBcraft.py]           ← strips PE headers, extracts raw shellcode
    │
    ▼
shellcode.bin           ← ready to embed in a loader or format with msfvenom
```

At runtime, the shellcode stub walks the PEB's InMemoryOrderModuleList to locate loaded modules and resolve API addresses by hash, with no import table required and no plaintext strings visible to scanners.

---

## Installation

**Requires Visual Studio 2019+ (Windows) and Python 3.8+**

```bash
# 1. Clone the repository
git clone https://github.com/whoamiamleo/PEBcraft
cd PEBcraft

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Open PEBcraft.slnx in Visual Studio
#    Build the project for x64 or x86 in Release configuration
#    (Project Properties -> C/C++ -> Code Generation -> Security Check -> Disable /GS-)

# 4. Run PEBcraft.py to extract the shellcode from the compiled binary
python PEBcraft.py -i PEBcraft/x64/Release/PEBcraft.exe -o shellcode.bin
```

---

## Usage

```
usage: PEBcraft.py [-h] -i INPUT -o OUTPUT

options:
  -h, --help           show this help message and exit
  -i, --input INPUT    path to input file (compiled PEBcraft.exe)
  -o, --output OUTPUT  path to output file (raw shellcode binary)
```

### Examples

```bash
# Extract x64 shellcode
python PEBcraft.py -i PEBcraft/x64/Release/PEBcraft.exe -o shellcode64.bin

# Convert to C array with msfvenom
msfvenom -p generic/custom PAYLOADFILE=shellcode64.bin -f C

# Test in a simple C loader
```
```c
#include <Windows.h>

int main(int argc, char* argv[]) {
    unsigned char buf[] = ...TRUNCATED...;

    void* p = VirtualAlloc(0, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    RtlMoveMemory(p, buf, sizeof(buf));
    HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)p, 0, 0, 0);
    WaitForSingleObject(hThread, INFINITE);

    return 0;
}
```

### Warnings

1. In Visual Studio, `Project Properties -> C/C++ -> Code Generation -> Security Check` must be set to **Disable Security Check (/GS-)** to prevent the compiler from inserting stack buffer overrun protection, which would break the position-independent shellcode.
2. Use the `XOR()` macro for all string literals to enforce compile-time encryption and ensure stack-based decryption at runtime. Strings not wrapped in `XOR()` will appear in plaintext in the compiled binary.

---

## Support

| Requirement | Details |
|---|---|
| Operating System | Windows (compilation requires Visual Studio) |
| Architecture | x64, x86 |
| Visual Studio | 2019 or later |
| Python | 3.8+ (for PEBcraft.py extraction script) |

## Formatting

### Input

The input to `PEBcraft.py` is a compiled **PEBcraft.exe** produced by Visual Studio in Release configuration (x64 or x86). The C source must use PEBcraft's PEB resolution macros and the `XOR()` macro for string literals.

### Output

The output is a raw **binary shellcode file** (`.bin`), stripped of all PE headers. It can be embedded directly in a loader or reformatted with tools like `msfvenom`:

```bash
msfvenom -p generic/custom PAYLOADFILE=shellcode.bin -f C
msfvenom -p generic/custom PAYLOADFILE=shellcode.bin -f py
msfvenom -p generic/custom PAYLOADFILE=shellcode.bin -f raw -o shellcode.bin
```

---

## Contributing

Contributions, issues, and feature requests are welcome. Feel free to check the [issues](https://github.com/whoamiamleo/PEBcraft/issues) page or submit a pull request.

## Attribution

If you use PEBcraft in a project or research, a mention or link back to this repository is appreciated.

- Author: Leopold von Niebelschuetz-Godlewski
- Repository: [https://github.com/whoamiamleo/PEBcraft](https://github.com/whoamiamleo/PEBcraft)
- License: MIT

---

## Legal & Ethics

PEBcraft is intended solely for authorized security testing and research activities. Any unauthorized use is strictly prohibited. The author assumes no responsibility for misuse or damage resulting from improper or unlawful use.

---

## License

MIT License

Copyright (c) 2026 Leopold von Niebelschuetz-Godlewski

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
