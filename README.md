# MalGen

MalGen is a cross-platform malware generator, used to interactively configure and generate malware executables and code snippets on the fly. 

The tool functions in such a way that allows the user to configure multiple options for various techniques like Encryption, Obfuscation, Payload Placement, Injections, etc. Once configured, the tool will compile a binary using semi-hardcoded C snippets reflecting the techniques and options the user selected.

## Installation
Using `git`:
```
git clone https://github.com/partyh4t/MalGen.git
```

Once the repository has been cloned, you can simply run `python3 malgen.py` to access the interactive prompt. I haven't gotten around to creating a `requirements.txt` file just yet, so keep in mind certain python modules may not be installed on your system. Typically you can install it with `pip install MODULE_NAME`

## Usage
Once within the prompt, running `help` or `?` will bring up a help menu, showcasing the various commands and modules available to you.

![image](https://github.com/user-attachments/assets/97bf3f4d-cc50-4b82-a4b0-8380f28bbcc0)


The program is designed to be used in the following way:
  1. Load a file containing shellcode into the program with `malgen> shellcode PATH/TO/SHELLCODE_FILE.bin`.(Adding shellcode generation via msfvenom within the program is something I have planned)
  2. Select and configure various techniques like Encryption, Obfuscation, Payload Placement, etc by entering the name of the technique you want to configure, this will alter the prompt and enter you into a different section specifically for configuring that technique. e.g. `malgen> encryption` -> `malgen::encryption>`.
  3. Each module/technique has specific settings you can configure and select, like aes, rc4, or xor, within the encryption module as an example. Selecting a specific technique can be done using `technique use`. So if for instance you want to specify your own xor key and then tell the program to use xor in the final binary, we could issue `xor key 01010101` alongside `xor use`. The order in which you run these commands does not matter.
  4. Once the desired modules and techniques have been selected and configured, issuing `malgen> generate` will combine the corresponding technique snippets into a final .c file, which is then compiled using `gcc`.

## Notes
This tool is still very early in development, and is lacking most major functionality. Especially as this is my first actual big project, expect the source code to be vomit-inducing and contain plenty of bugs.

At this point in time, the program does not generate a final compiled binary, but instead prints out the snippets with the configurations applied to the terminal. This way the tool can atleast still provide some use for the time being.

More module/technique specific documentation coming soon.
