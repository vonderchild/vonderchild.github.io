---
title: HackTheBox - Baby RE
author:
  name: wonderchild
  link: https://twitter.com/vonderchild
date: 2022-07-02 9:00:00
categories: [HackTheBox, Intro to Reversing]
tags: [CTF, HTB]
---

Welcome folks. This is a writeup for the first challenge from Intro to Reversing track on HackTheBox.

The challenge description states:

`Show us your basic skills! (P.S. There are 4 ways to solve this, are you willing to try them all?)`

We are provided with a file named `auth`. Let ys begin by checking file type and metadata. For this purpose, I’ll use the `file` command which lets you see the type of *file* you're dealing with.

![file](/assets/img/intro-to-rev/baby/baby1.png)

The output shows that it is a 64-bit executable and linkable format file. 

# Method 1 - Strings

---

Let’s use the `strings` utility to find any hardcoded strings inside the binary.

![strings](/assets/img/intro-to-rev/baby/baby2.png)

The output reveals the hardcoded key.

# Method 2 - Ltrace

---

Let’s now try using `ltrace` utility to see what library calls are being made by the binary.

![wonderchild@kali(13).png](/assets/img/intro-to-rev/baby/baby3.png)

The output gives the correct key against which comparison is made.

# Method 3 - Ghidra

```c
undefined8 main(void)

{
  int iVar1;
  undefined8 local_48;
  undefined8 local_40;
  undefined4 local_38;
  undefined2 local_34;
  char local_28 [24];
  char *local_10;
  
  local_10 = "Dont run `strings` on this challenge, that is not the way!!!!";
  puts("Insert key: ");
  fgets(local_28,0x14,stdin);
  iVar1 = strcmp(local_28,"abcde122313\n");
  if (iVar1 == 0) {
    local_48 = 0x594234427b425448;
    local_40 = 0x3448545f5633525f;
    local_38 = 0x455f5354;
    local_34 = 0x7d5a;
    puts((char *)&local_48);
  }
  else {
    puts("Try again later.");
  }
  return 0;
}
```

The code reveals both the correct key as well as the flag (in hexadecimal).

# Method 4 - Radare2

![radare2](/assets/img/intro-to-rev/baby/baby4.png)

The code reveals both the correct key as well as the flag (in hexadecimal).

That’s All Folks. Have a great day!