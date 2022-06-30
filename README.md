
# VM-Challenge

A Simple VM-based challenge created using the academic tigress obfuscator




## Compiling

Prerequisites:

 - Tigress Obfuscator
 - GCC

```bash
tigress --Environment=x86_64:Linux:Gcc:4.6 --Transform=Virtualize --VirtualizeDispatch=switch --VirtualizeOperands=stack --Functions=secret_key --out=PATH_TO_DIR/vm_chal.c PATH_TO_DIR/vm_challenge.c 
```

Compling tigress output file with GCC and Stripping Binary
```bash
gcc vm_chal.c -o vm_chal.bin -fno-stack-protector -z execstack -no-pie && strip vm_chal.c
```

### Note:

This challenge was compiled using tigress version 3.3.2 and GCC version 9.4.0

I solved this challenge using Automated Analysis Through Symbolic Execution, below is the resource I took inspiration from

https://github.com/mrphrazer/r2con2021_deobfuscation

Tim Blazytko has been a huge help during my endeavour into Symbolic Execution and has released invaluable resources to help others to better understand the true power of Symbolic Execution and how helpful it is with Binary Obfuscation.
