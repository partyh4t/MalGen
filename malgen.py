## MalGen ##

# I want to create an interactive prompt, sort of like mimikatz, where you can select various different methods and techniques, and have it generate a final executable or the source code/snippets of the techniques theyve chosen.

# 1. Setup interactive prompt to take input from the user. -- DONE
# 2. Have certain sections for each set of "techniques", eg "Encryption", "Obfuscation", "Payload Placement", etc.
# 3. For our snippets, we'll create a specific .py file for each, eg encryption_snippets.py, obfuscation_snippets.py, and within those files we'll be able to inject our variables and configuration options into the snippets, and then we can transfer everything at the end to a .c file for compilation.
# 4. Add option for the user to either provide a .bin file containing the shellcode or paste it into the prompt (although pasting will probably prove to be a pain), so preferably the .bin file.

# Extra features to add later:
# 1. Allow generation solely via CLI without interactive prompt. How I'll implement that, not sure yet.
# 2. If I'm feeling frisky, once all is done I can try implementing a GUI??
# 3. A "generate" command that will generate the final executable or source code based on the techniques the user has chosen.
# 4. Some kind of seperate "config" file that will store the user's chosen techniques and configuration, so they can come back to it later and generate the same thing again.
# 5. Functionality that lets the user generate small things like shellcode, snippets, encrypting/decrypting strings, etc.
# 6. Add randomization to the techniques, eg randomizing the encryption key, obfuscation methods, to ensure that the generated code is unique each time.
# 7. Add msfvenom functionality so that the shellcode can be generated and utilized directly, without the need for a .bin file.

# Visualizing it:
# User types for example: "encryption", and that takes them to a encryption-specific prompt, where typing something like help would result in listing all the possible "modules" available for encryption, eg AES, RC4, XOR.
# If say, the user wants to utilize XOR, they could provide something like "xor help" to list possible alterations to make to the snippet/module. So like "xor key 9" to make the key 9 or something, or "aes key KEY_HERE" if the user wants to provide their own encryption/decryption key.

import cmd
#import readline
from modules import encryption
from modules.encryption import EncryptionModule
from modules.obfuscation import ObfuscationModule
from snippets.encryption_snippets import *
from snippets.obfuscation_snippets import *

colors = ["\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[95m", "\033[96m", "\033[97m"]

ascii_art = f"""{colors[0]}
 ███▄ ▄███▓ ▄▄▄       ██▓      ▄████ ▓█████  ███▄    █ 
▓██▒▀█▀ ██▒▒████▄    ▓██▒     ██▒ ▀█▒▓█   ▀  ██ ▀█   █ 
▓██    ▓██░▒██  ▀█▄  ▒██░    ▒██░▄▄▄░▒███   ▓██  ▀█ ██▒
▒██    ▒██ ░██▄▄▄▄██ ▒██░    ░▓█  ██▓▒▓█  ▄ ▓██▒  ▐▌██▒
▒██▒   ░██▒ ▓█   ▓██▒░██████▒░▒▓███▀▒░▒████▒▒██░   ▓██░
░ ▒░   ░  ░ ▒▒   ▓▒█░░ ▒░▓  ░ ░▒   ▒ ░░ ▒░ ░░ ▒░   ▒ ▒ 
░  ░      ░  ▒   ▒▒ ░░ ░ ▒  ░  ░   ░  ░ ░  ░░ ░░   ░ ▒░
░      ░     ░   ▒     ░ ░   ░ ░   ░    ░      ░   ░ ░ 
       ░         ░  ░    ░  ░      ░    ░  ░         ░ 
\033[0m"""



class MalgenShell(cmd.Cmd):
    prompt = "malgen> " # sets custom prompt

    def do_encryption(self, arg):
        """Enter encryption configuration mode."""
        EncryptionModule().cmdloop() # starts the encryption module prompt.

    def do_obfuscation(self, arg):
        """Enter obfuscation configuration mode."""
        ObfuscationModule.cmdloop() # starts the obfuscation module prompt.

    def do_generate(self, arg):
        """Generate the final executable or source code."""
        snippet_encryption = get_encryption_method(encryption.encryption_method, encryption.shellcode, encryption.use_key, encryption.iv) # get the encryption snippet
        print(snippet_encryption)

    def do_exit(self, arg):
        """Exit the interactive shell."""
        print("Exiting...")
        return True

if __name__ == "__main__":
    MalgenShell().cmdloop(intro=(ascii_art + "\nWelcome to MalGen. Type help or ? to list commands.\n")) # starts the prompt loop.