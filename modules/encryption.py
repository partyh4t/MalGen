# MalGen's encryption module

import cmd
import shlex
from snippets.encryption_snippets import *

encryption_method = None
encryption_methods = ["none", "xor", "aes", "rc4"]
enc_shellcode = "" # the encrypted shellcode.
key = None  # if user provides their own key, we'll use that ofc. If not, we'll generate a random key. same with IV.
iv = ""
shellcode = b"\xfc\x48\x83\xe4\xf0" # the shellcode to be encrypted.

class EncryptionModule(cmd.Cmd):
    prompt = "malgen::encryption> " # sets custom prompt
    
   # XOR encryption
    def do_xor(self, arg):
        """\nConfigure XOR encryption. - Usage: xor <option> <arg>\n
Options:
    key <key> - Set the encryption key.
    encrypt <data> - Encrypt the provided data.
    decrypt <data> - Decrypt the provided data.\n"""
        try:
            arg1, arg2 = shlex.split(arg)
        except ValueError:
            print(f"Usage: xor <option> <arg>")
        if arg1 == "key":
            global key
            key = arg2
            print(f"\nEncryption key set to: {key}\n")


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


    # RC4 encryption
    def do_rc4(self, arg):
        """\nConfigure RC4 encryption. - Usage: rc4 <option> <arg>\n"""


    # add func for showing currently selected encryption method and its settings, eg show xor would print something similar to help xor, but showing the currently configured ones
    def do_show(self, arg):
        """\nShows the currently selected encryption method and options. - Usage: show <option>\n
Options:
    <xor> - Shows the configuration settings for XOR.
    <rc4> - Shows the configuration settings for RC4.
    <aes> - Shows the configuration settings for AES.
    # If left empty, shows the currently selected encryption method.\n"""
        if encryption_method:
            print(f"\nCurrently selected encryption method: {encryption_method}\n")
        else:
            print("\nNo encryption method selected.\n")



    def do_use(self, arg):
        """\nUses the given encryption method in the final executable. - Usage: use <aes/xor/rc4/none>\n"""
        if arg not in encryption_methods:
            print(f"\nInvalid encryption method. Available methods: {encryption_methods}\n")
        else:
            global encryption_method
            encryption_method = arg
            print(f"\nSelected encryption method: {encryption_method}\n")


    def do_options(self, arg):
        """\nLists available encryption methods.\n"""
        print(f"\nAvailable encryption methods: {encryption_methods}\n")


    def emptyline(self):
        pass


    def do_exit(self, arg):
        """\nExits the encryption module.\n"""
        return True


