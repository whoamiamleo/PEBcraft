# PEBcraft v1.0
A utility that transforms C source code into position-independent shellcode which resolves Windows APIs using the PEB (Process Environment Block).

---

## Features

- **Dynamic PEB Resolution**: Resolves Windows API functions directly via the Process Environment Block (PEB), bypassing the Import Address Table (IAT) to minimize forensic footprint.
- **Multi-Architecture Support**: Generates position-independent x86 and x64 assembly code directly from C source.
- **API Obfuscation**: Employs bit-mixed hashing for module and function names to defeat both static and dynamic string analysis tools.
- **Encrypted String Literals**: Implements compile-time string encryption with stack-based runtime decryption to defeat static string analysis tools.
- **Streamlined Shellcode Development**: Simplifies the creation of sophisticated, weaponized payloads for offensive security research and red team operations.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/whoamiamleo/PEBcraft
cd PEBcraft
```

Install python dependencies:
```bash
pip install -r requirements.txt
```

---

## Getting Started

1. Open `PEBcraft.slnx` in Visual Studio and build the project for x64 or x86.
2. Run the `PEBcraft.py` utility to extract the shellcode from the compiled executable.
3. Embed the extracted shellcode into your own projects and refer to the `Usage` section for an example.

---

## Usage
```console
usage: PEBcraft.py [-h] -i INPUT -o OUTPUT

options:
  -h, --help           show this help message and exit
  -i, --input INPUT    path to input file
  -o, --output OUTPUT  path to output file
```

Basic usage example:
```bash
python PEBcraft.py -i PEBcraft/x64/Release/PEBcraft.exe -o 64.bin
msfvenom -p generic/custom PAYLOADFILE=64.bin -f C
```

Testing shellcode in C:
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

1. In Visual Studio, `Project Properties -> C/C++ -> Code Generation -> Security Check -> Disable Security Check (/GS-)` must be configured to disable the compiler's stack buffer overrun protection so no security cookie checks are generated in the compiled code.
2. Utilize the `XOR()` macro for all string literals to enforce compile-time encryption and ensure stack-based decryption at runtime, preventing plaintext strings from appearing in the binary.

---

## Attribution

Written by Leopold von Niebelschuetz-Godlewski

[https://github.com/whoamiamleo/PEBcraft](https://github.com/whoamiamleo/PEBcraft)

Licensed under the MIT License.

If you use PEBcraft in your projects, a link back or mention is appreciated!

---

## Contributing
Contributions, issues, and feature requests are welcome!
Feel free to check the [issues](https://github.com/whoamiamleo/PEBcraft/issues) page or submit a pull request.

---

## License
This project is licensed under the MIT License — see the [LICENSE](https://raw.githubusercontent.com/whoamiamleo/PEBcraft/main/LICENSE) file for details.