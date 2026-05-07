import argparse, pefile
from colorama import init, Fore, Back, Style

# FUNCTIONS
init(autoreset=True) # reset after each print
def colorText(text, fg=None, bg=None, style=None):
    result = ''
    if style:
        result += style
    if fg:
        result += fg
    if bg:
        result += bg
    result += text
    return result

def extractShellcode(exePath, outputFile):
    pe = pefile.PE(exePath)
    for section in pe.sections:
        name = section.Name.decode().strip('\x00')
        if name == ".text":
            shellcode = section.get_data().rstrip(b'\x00')
            shellcodeLen = len(shellcode)
            if open(outputFile,"wb").write(shellcode) == shellcodeLen:
                print(colorText("[w00t]", fg=Fore.GREEN), f"Wrote shellcode to \"{outputFile}\" ({shellcodeLen} bytes)")
                return
    raise Exception("Could not find \".text\" section!")

# MAIN
if __name__ == "__main__":
    print(colorText(r"""
                    ██████╗ ███████╗██████╗
                    ██╔══██╗██╔════╝██╔══██╗
                    ██████╔╝█████╗  ██████╔╝
                    ██╔═══╝ ██╔══╝  ██╔══██╗
                    ██║     ███████╗██████╔╝
                    ╚═╝     ╚══════╝╚═════╝craft""", fg=Fore.RED))
    print(r"""                      PEBcraft — Version 1.0
 A utility that transforms C source code into position-independent shellcode
   which resolves Windows APIs using the PEB (Process Environment Block).


      Written by: Leopold von Niebelschuetz-Godlewski
         https://github.com/whoamiamleo/PEBcraft

              Licensed under the MIT License
""")

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help='path to input file'
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help='path to output file'
    )

    args = parser.parse_args()

    try:
        extractShellcode(args.input, args.output)
    except Exception as e:
        print(colorText("[ERROR]", fg=Fore.RED), e)