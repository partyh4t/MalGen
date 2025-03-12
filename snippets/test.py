
# currently beig used for testing purposes
'''
key = input("> ")

print(key)
print(type(key))
print(bytes([int(key, 2)]))
'''

shellcode = b"\x90\x90\xCC\x90\xCC"
print(shellcode)