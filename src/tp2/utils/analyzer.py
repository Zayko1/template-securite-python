import os
import re
import string

import capstone

try:
    import pylibemu
    _PYLIBEMU = True
except ImportError:
    _PYLIBEMU = False

try:
    import anthropic
    _ANTHROPIC = True
except ImportError:
    _ANTHROPIC = False


def parse_shellcode_file(filepath: str) -> bytes:
    """Parse a file containing shellcode in \\xNN format, one or multiple lines."""
    with open(filepath, "r") as f:
        content = f.read()
    hex_bytes = re.findall(r"\\x([0-9a-fA-F]{2})", content)
    if not hex_bytes:
        raise ValueError(f"Aucun octet \\xNN trouve dans {filepath}")
    return bytes(int(h, 16) for h in hex_bytes)


def get_shellcode_strings(shellcode: bytes, min_length: int = 4) -> list[str]:
    """
    Extraire les chaines de caracteres ASCII imprimables du shellcode
    (similaire a la commande `strings`).
    """
    results = []
    current: list[str] = []
    printable = set(string.printable) - set("\t\n\r\x0b\x0c")
    for byte in shellcode:
        char = chr(byte)
        if char in printable:
            current.append(char)
        else:
            if len(current) >= min_length:
                results.append("".join(current))
            current = []
    if len(current) >= min_length:
        results.append("".join(current))
    return results


def get_pylibemu_analysis(shellcode: bytes) -> str:
    """
    Emuler le shellcode avec pylibemu pour obtenir le profil d'execution.
    Fallback sur une detection heuristique si pylibemu n'est pas disponible.
    """
    if _PYLIBEMU:
        try:
            e = pylibemu.Emulator(outputpath="/tmp/tp2_emu")
            e.run(shellcode)
            return e.emu_profile_output or "Aucun profil genere"
        except Exception as exc:
            return f"Erreur pylibemu : {exc}"

    # Fallback : heuristiques GetPC + NOP sled
    lines = ["[pylibemu non disponible - analyse heuristique]"]

    nop_count = shellcode.count(b"\x90")
    if nop_count >= 4:
        lines.append(f"NOP sled detecte : {nop_count} octets 0x90")

    if b"\xe8\x00\x00\x00\x00" in shellcode:
        lines.append("GetPC : pattern CALL+0 detecte (self-referencing call)")
    if b"\xd9\xee\xd9\x74\x24\xf4" in shellcode:
        lines.append("GetPC : pattern FSTENV detecte")

    strings = get_shellcode_strings(shellcode)
    api_keywords = ["kernel32", "ntdll", "LoadLibrary", "GetProcAddress",
                    "WinExec", "CreateProcess", "cmd", "powershell", "urlmon"]
    found = [s for s in strings if any(k.lower() in s.lower() for k in api_keywords)]
    if found:
        lines.append(f"API/DLL Windows references : {found}")

    lines.append(f"Taille totale : {len(shellcode)} octets")
    return "\n".join(lines)


def get_capstone_analysis(shellcode: bytes) -> str:
    """
    Desassembler le shellcode en x86 32-bit avec Capstone.
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = False

    lines = []
    for insn in md.disasm(shellcode, 0x1000):
        lines.append(f"0x{insn.address:04x}:  {insn.mnemonic:<8} {insn.op_str}")

    return "\n".join(lines) if lines else "Aucune instruction decodee"


def get_llm_analysis(shellcode: bytes) -> str:
    """
    Envoyer le shellcode a un LLM (Claude) pour obtenir une explication detaillee.
    Utilise les strings et le desassemblage comme contexte.
    """
    if not _ANTHROPIC:
        return "Erreur : SDK anthropic non disponible (pip install anthropic)"

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return "Erreur : ANTHROPIC_API_KEY non definie dans l'environnement"

    strings = get_shellcode_strings(shellcode)
    disassembly = get_capstone_analysis(shellcode)

    hex_repr = " ".join(f"\\x{b:02x}" for b in shellcode)

    prompt = f"""Tu es un expert en reverse engineering et en analyse de malwares.
Analyse le shellcode x86 32-bit suivant et explique precisement ce qu'il fait.

**Taille :** {len(shellcode)} octets

**Chaines de caracteres extraites :**
{strings if strings else "Aucune"}

**Desassemblage (Capstone x86-32) :**
{disassembly}

**Shellcode brut (hex) :**
{hex_repr}

Explique en francais :
1. Le comportement general du shellcode (que fait-il ?)
2. Les techniques utilisees (resolution de l'API Windows, GetPC, etc.)
3. Les IOCs (indicateurs de compromission) : DLLs, fonctions Windows, adresses IP, commandes, chemins
4. Le niveau de dangerosité et la famille probable (meterpreter, reverse shell, downloader, etc.)
"""

    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model="claude-opus-4-7",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text
