# MalGen's encryption module

import cmd

encryption_method = None
encryption_methods = ["none", "xor", "aes", "rc4"]
enc_shellcode = "" # the encrypted shellcode.
key = "" # if user provides their own key, we'll use that ofc. If not, we'll generate a random key. same with IV.
iv = ""

class EncryptionModule(cmd.Cmd):
    prompt = "malgen::encryption> " # sets custom prompt

    def do_use(self, arg):
        """\nSelect an encryption method.\n Usage: use <method>\n"""
        if arg not in encryption_methods:
            print(f"\nInvalid encryption method. Available methods: {encryption_methods}\n")
        else:
            global encryption_method
            encryption_method = arg
            print(f"\nSelected encryption method: {encryption_method}\n")
    
    def do_options(self, arg):
        """\nList available encryption methods.\n"""
        print(f"\nAvailable encryption methods: {encryption_methods}\n")

    def do_selected(self, arg):
        """\nShow selected encryption method.\n"""
        print(f"\nCurrent encryption method: {encryption_method}\n")
    
    def do_exit(self, arg):
        """\nExit the encryption module.\n"""
        return True

    def emptyline(self):
        pass


    # AES encryption
    def do_aes(self, arg):
        """\nConfigure AES encryption. - Usage: aes <option> <arg>\n
Options: 
    key <key> - Set the encryption key.
    iv <iv> - Set the initialization vector.
    mode <mode> - Set the encryption mode (eg CBC, ECB, CFB, OFB).
    padding <padding> - Set the padding mode (eg PKCS5, PKCS7, ISO10126).
    encrypt <data> - Encrypt the provided data.
    decrypt <data> - Decrypt the provided data.\n""" # can include optional/default values for the args



    # XOR encryption
    def do_xor(self, arg):
        """\nConfigure XOR encryption. - Usage: xor <option> <arg>\n
Options:
    key <key> - Set the encryption key.
    encrypt <data> - Encrypt the provided data.
    decrypt <data> - Decrypt the provided data.\n"""
        
        if arg == key:
            global key
            key = arg
            print(f"\nEncryption key set to: {key}\n")
