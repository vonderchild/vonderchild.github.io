---
title: Introduction to CryptoHack
author:
  name: wonderchild
  link: https://twitter.com/vonderchild
date: 2022-04-05 4:20:00 +0000
categories: [crypto]
tags: [crypto, CryptoHack]
---

## ASCII

ASCII is a 7-bit encoding standard which allows the representation of text using the integers 0-127.

Using the below integer array, convert the numbers to their corresponding ASCII characters to obtain a flag.

```
[99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]
```

### Solution

```python
ascii = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]

print("".join([chr(x) for x in ascii]))
```

## Hex

When we encrypt something the resulting ciphertext commonly has bytes  which are not printable ASCII characters. If we want to share our encrypted data, it's common to encode it into something more user-friendly and portable across different systems.

Included below is a flag encoded as a hex string. Decode this back into bytes to get the flag.

```
63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d
```

### Solution

```python
hex = "63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d"

print(bytes.fromhex(hex))
```

## Base64

Another common encoding scheme is Base64, which allows us to represent binary data as an ASCII string using 64 characters. One character of a Base64 string encodes 6 bits, and so 4 characters of Base64 encode three 8-bit bytes.

Base64 is most commonly used online, so binary data such as images can be easily included into HTML or CSS files.

Take the below hex string, *decode* it into bytes and then *encode* it into Base64.

```
72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf
```

### Solution

```python
import base64

string = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"

bytess = bytes.fromhex(string)
print(base64.b64encode(bytess))
```

## Bytes and Big Integers

Cryptosystems like RSA works on numbers, but messages are made up of characters. How should we convert our messages into numbers so that mathematical operations can be applied?

The most common way is to take the ordinal bytes of the message, convert them into hexadecimal, and concatenate. This can be interpreted as a base-16 number, and also represented in base-10.

To illustrate:

```
message:      HELLO
ascii bytes:  [72, 69, 76, 76, 79]
hex bytes:    [0x48, 0x45, 0x4c, 0x4c, 0x4f]
base-16:      0x48454c4c4f
base-10:      310400273487
```

Convert the following integer back into a message:

```
11515195063862318899931685488813747395775516287289682636499965282714637259206269
```

### Solution

```python
from Crypto.Util.number import *

n = 11515195063862318899931685488813747395775516287289682636499965282714637259206269 

print(long_to_bytes(n))
```

## XOR Starter

XOR is a bitwise operator which returns 0 if the bits are the same, and 1 otherwise. In textbooks the XOR operator is denoted by ⊕, but in most challenges and programming languages you will see the caret `^` used instead.

For longer binary numbers we XOR bit by bit: `0110 ^ 1010 = 1100`. We can XOR integers by first converting the integer from decimal to binary. We can XOR strings by first converting each character to the integer representing the Unicode character.  

Given the string `"label"`, XOR each character with the integer `13`. Convert these integers back to a string and submit the flag as `crypto{new_string}`.

### Solution

```python
string = "label"

ords = [ord(x) for x in string]

xored = [x ^ 13 for x in ords]

string = "".join([chr(x) for x in xored])

print(string)
```

## XOR Properties

In the last challenge, you saw how XOR worked at the level of bits. In this one, we're going to cover the properties of the XOR operation and then use them to undo a chain of operations that have encrypted a flag. Gaining an intuition for how this works will help greatly when you come to attacking real cryptosystems later, especially in the block ciphers category.

There are four main properties we should consider when we solve challenges using the XOR operator

```
Commutative: A ⊕ B = B ⊕ A
Associative: A ⊕ (B ⊕ C) = (A ⊕ B) ⊕ C
Identity: A ⊕ 0 = A
Self-Inverse: A ⊕ A = 0
```

Let's break this down. Commutative means that the order of the XOR operations is not important. Associative means that a chain of operations can be carried out without order (we do not need to worry about brackets). The identity is 0, so XOR with 0 "does nothing", and lastly something XOR'd with itself returns zero.

Let's try this out in action! Below is a series of outputs where three random keys have been XOR'd together and with the flag. Use the above properties to undo the encryption in the final line to obtain the flag.

```
KEY1 = a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313
KEY2 ^ KEY1 = 37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e
KEY2 ^ KEY3 = c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1
FLAG ^ KEY1 ^ KEY3 ^ KEY2 = 04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf
```

### Solution

### Long Solution

```python
def xor(str1, str2):
    return "%x" % (int(str1, 16) ^ int(str2, 16))

key1 = "a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313"
key2x1 = "37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e"
key2x3 = "c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1"
flagx1x2x3 = "04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf"

key2 = xor(key1, key2x1)

key3 = xor(key2x3, key2)

flag = xor(flagx1x2x3, key1)
flag = xor(flag, key2)
flag = xor(flag, key3)

print(bytes.fromhex(flag))
```

### Direct Solution

```python
def xor(str1, str2):
    return "%x" % (int(str1, 16) ^ int(str2, 16))

key1 = "a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313"
key2x1 = "37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e"
key2x3 = "c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1"
flagx1x2x3 = "04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf"

print(bytes.fromhex(xor(xor(flagx1x2x3, key2x3), key1)))
```

## Favourite byte

For the next few challenges, you'll use what you've just learned to solve some more XOR puzzles.

I've hidden some data using XOR with a single byte, but that byte is a secret. Don't forget to decode from hex first.

```
73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d
```

### Solution

### Bruteforce

```python
string = "73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d"

decoded = bytes.fromhex(string).decode()

for i in range(256):
    string = [ord(x) ^ i for x in decoded]
    string = "".join([chr(x) for x in string])
    if "crypto" in string:
        print(string)
```

### Better Solution

```python
string = "73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d"
decoded = bytes.fromhex(string).decode()

key = ord(decoded[0]) ^ ord("c")
print("".join([chr(ord(i) ^ key) for i in decoded]))
```

## You either know, XOR you don't

I've encrypted the flag with my secret key, you'll never be able to guess it.

`0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104`

### Solution

```python
from pwn import xor

stringg = "0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104"

decoded = bytes.fromhex(stringg)

key = xor(decoded[:7], "crypto{")
key += b"y"

print(xor(decoded, key))
```