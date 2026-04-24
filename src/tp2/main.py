import argparse
import os
import sys

# Allow running directly: python3 main.py -f shellcode.txt
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from tp2.utils.analyzer import (
    get_capstone_analysis,
    get_llm_analysis,
    get_pylibemu_analysis,
    get_shellcode_strings,
    parse_shellcode_file,
)
from tp2.utils.config import logger


def main():
    parser = argparse.ArgumentParser(description="TP2 - Shellcode Analyzer")
    parser.add_argument("-f", "--file", required=True, help="Fichier shellcode (.txt)")
    args = parser.parse_args()

    shellcode = parse_shellcode_file(args.file)
    logger.info(f"Testing shellcode of size {len(shellcode)}B")

    strings = get_shellcode_strings(shellcode)
    if strings:
        logger.info(f"Strings found: {strings}")
    else:
        logger.info("Strings found: aucune chaine imprimable trouvee")

    emu_result = get_pylibemu_analysis(shellcode)
    logger.info(f"Pylibemu analysis:\n{emu_result}")

    asm_result = get_capstone_analysis(shellcode)
    logger.info(f"Capstone disassembly:\n{asm_result}")

    llm_result = get_llm_analysis(shellcode)
    logger.info(f"Explication LLM :\n{llm_result}")

    logger.info("Shellcode analysed !")


if __name__ == "__main__":
    main()
