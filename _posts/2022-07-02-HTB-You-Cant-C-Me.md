---
title: HackTheBox - You Cant C Me
author:
  name: wonderchild
  link: https://twitter.com/vonderchild
date: 2022-07-02 9:45:00
categories: [HackTheBox, Intro to Reversing]
tags: [CTF, HTB]
---

Welcome folks. This is a writeup for the second challenge from Intro to Reversing track on HackTheBox.

The challenge description states:

`Find the password (say PASS) and enter the flag in the form HTB{PASS}`

We are provided with a file named `auth`. Let ys begin by checking file type and metadata. For this purpose, I’ll use the `file` command which lets you see the type of *file* you're dealing with.

![file](/assets/img/intro_to_rev/you_cant_c_me/img1.png)

The output does not reveal much except that it is a 64-bit executable and linkable format file. Moreover, it is stripped off of its symbols including function names. Using `strings` utility as well does not yeild much about the file except an odd string `this_is_the_password` which turns out to be a rabbit hole.

Before firing up ghidra or radare2 for reversing the binary, let’s try using `ltrace` utility to see what library calls are being made by the binary.

![ltrace](/assets/img/intro_to_rev/you_cant_c_me/img2.png)

The `strcmp` call being made reveals the actual password being compared with the input. Running the binary and entering `wh00ps!_y0u_d1d_c_m3` as input prints the flag.

# Post challenge completion — Static Analysis

---

Let’s now fire up ghidra and begin reversing the binary. 

Following is not the actual reverse engineered code, I have renamed a few variables to make the code understandable.

```c
undefined4 main(void)

{
  int result;
  undefined8 local_48;
  undefined8 local_40;
  undefined4 local_38;
  char *input_password;
  undefined8 local_28;
  undefined8 local_20;
  undefined4 local_18;
  undefined local_14;
  int i;
  undefined4 local_c;
  
  local_c = 0;
  i = 0;
  printf("Welcome!\n");
  local_28 = 0x5f73695f73696874;
  local_20 = 0x737361705f656874;
  local_18 = 0x64726f77;
  local_14 = 0;
  input_password = (char *)malloc(0x15);
  local_48 = 0x5517696626265e6d;
  local_40 = 0x555a275a556b266f;
  local_38 = 0x29635559;
  for (i = 0; i < 0x14; i = i + 1) {
    *(char *)((long)&local_28 + (long)i) = *(char *)((long)&local_48 + (long)i) + '\n';
  }
  fgets(input_password,0x15,stdin);
  result = strcmp((char *)&local_28,input_password);
  if (result == 0) {
    printf("HTB{\%s}\n",input_password);
  }
  else {
    printf("I said, you can\'t c me!\n");
  }
  return local_c;
}
```

The code starts with declaring a few local variables, whose values are defined after it prints `Welcome`. The loop adds a decimal value of `10` in the character stored at address pointed towards by `local_48` + `i`. The loop is run for 20 iterations modifying character stored at address pointed towards by `local_48` + `i` and adding a decimal value of `10` (char `\n`)  to it and storing at the address pointed towards by `local_28` + `i`.

I wrote a python script to perform the steps mentioned above and print out the flag.

```python
import binascii

local_48 = "0x5517696626265e6d"[2:]
local_40 = "0x555a275a556b266f"[2:]
local_38 = "0x29635559"[2:]

part1 = binascii.unhexlify(local_48)
part2 = binascii.unhexlify(local_40)
part3 = binascii.unhexlify(local_38)

flag1 = ""
flag2 = ""
flag3 = ""

for char in part1:
    flag1 += chr(char + 10)

for char in part2:
    flag2 += chr(char + 10)

for char in part3:
    flag3 += chr(char + 10)

flag = flag1[::-1] + flag2[::-1] + flag3[::-1]
print(flag)
```

# Post challenge completion — Dynamic Analysis

---

I will use radare2 and gdb with its extension `pwndbg`. 

![pwndbg](/assets/img/intro_to_rev/you_cant_c_me/img3.png)

Let’s print out the disassembled main function and set up a break point right before the `strcmp` function is called.

![radare2](/assets/img/intro_to_rev/you_cant_c_me/img4.png)

![breakpoint](/assets/img/intro_to_rev/you_cant_c_me/img5.png)

When the breakpoint is reached, we find the correct password inside `RDI` register.

# More Tinkering

Let’s set a breakpoint inside the loop and get the flag value printed inside the iterations.

![ghidra](/assets/img/intro_to_rev/you_cant_c_me/img6.png)

![final](/assets/img/intro_to_rev/you_cant_c_me/img7.png)

That’s All Folks. Have a great day!