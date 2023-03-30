---
title: Doe, a deer — DeconstruCT.F 2021
author: wonderchild
date: 2021-10-02 4:20:00 -0700
categories: [crypto]
tags: [crypto]
img_path: /assets/img/posts/deconstructf/
---

---

Last week, my team and I took part in DeconstruCT.F, a 24-hour Capture The Flag event organized by the Google Developers Student Club at Vellore Institute of Technology. It was an exciting competition, and after 24 hours of no sleep, we emerged as winners. Among the challenges I solved in different categories including Cryptography, Web, Forensics, the one that really intrigued me and motivated me to write about was a Cryptography challenge called “Doe, A Deer”. The challenge was worth 500 points, involved studying about music theory, then manually deciphering a music sheet cipher, and at the end of the competition, only three teams managed to solve it. So, with out further ado, let's get started.

## Challenge Description

Mark, a very gifted musician, is suddenly missing after his music class. He is said to have been upset after turning in his assignment. He had worked very hard on it, it was his first original. Here, you can see his work. I'm sure you can find him, he wouldn't have gone far.

### Files Attached

- Doe a deer.pdf
- tune_700.mp3

## Solution

Lets begin by analyzing the files we've been given. A quick look at the pdf file reveals that it is a `Music Sheet Cipher`. 

Let's see whether there's a deciphering tool available online. A quick google search for 
Music Sheet cipher decoding tool takes us to [dcode.fr](https://www.dcode.fr/music-sheet-cipher). I tried decoding it, but the tool gave me gibberish. 

If that's not going to work, then let's get back to our old pal Google and search for Music Sheet Ciphers. The second search from the top leads to [this website](https://wmich.edu/mus-theo/solfa-cipher), which is a `Solfa Cipher` online encoding tool. Let's try encoding something and check whether the result matches the ciphertext we've been given.

Hmm. It does in a way. Let's play about with it a little and see if we can come up with a ciphertext that's similar to the pdf one. I couldn't do it. However, we're certain it's `Solfa Cipher` now. 
Let's find an online decoder and get the flag. Child's play right? But guess what? 

There's no online decoding tool for it. We will have to decipher it manually.

Back to google, I found [this writeup](https://www.deepcode.ca/index.php/2017/06/10/the-solfa-cipher-nsec17-write-up/) from 2017 which states:

> Each note is linked to the seven pitches of the solfege, i.e. Do (D), Re (R), Mi (M), Fa (F), Sol (S), La (L) and Si(T).

![Figure 1](figure1.png)

The columns represent the pitch, while the rows represent the time units for each note `(1, 2, 3 or 4)`. It's mentioned in the writeup that the key is defined using a `clef`, a `tonic`, a `mode` and a `rythmic unit`. 

These `4` elements when combined, generate a key which can be used for both encryption and decryption. We know that the first line of the pdf is the key used for encryption which means we can figure out the settings of the 4 elements. I tried multiple settings on [this website](https://wmich.edu/mus-theo/solfa-cipher/secrets/) to see if I could get the same key as we have. Luckily, with `Treble` as the `Clef`, `C` as the `tonic`, `Major` as the `Mode`, and `Eight` as the `rythmic unit` I was able to get the original key back.

![Figure 2](figure2.png)

The given key specifies a *`1/8`* rhythm, as such an [Eighth](https://en.wikipedia.org/wiki/Eighth_note) note will be worth `1-time unit`, a [Quarter](https://en.wikipedia.org/wiki/Quarter_note) note will be worth `2-time units` and the [half note](https://en.wikipedia.org/wiki/Half_note) will be worth `4-time units`. 

After studying a little bit of music theory I was able to figure out that a `.` with a music note meant `n+1` time units. At this point, I had a good understanding of how the `Solfa Cipher` worked, but I wasn't sure what the `z-like` looking note signified, so I asked the admin about it, and he answered that it's a buffer character worth a `2-time unit`.

Using the Key, we can write out the correct scale with its associated solfege syllables `(Do, Re, Mi, Fa, So, La, Ti)` and divide up the rhythms into counts of four `8th` notes. The first downbeat is always `1`.

Let's start mapping the counts onto the pdf. I have tried to explain the mapping process in the following diagram.

![Figure 3](figure3.png)

We're done with the hard part, now we just need to know the alphabet equivalents of all solfege syllables. We can easily find the solfege syllables' alphabets equivalent on google.

![Figure 4](figure4.png)

We have got all we need to decrypt the ciphertext. Let's begin the process.

![Figure 5](figure5.png)

After applying the above process on all of the ciphertext, you'll end up with:

`R,1 M,1 F,3 F,1 T,1 D,3 D,3 R,4 F,3 T,1 F,3 R,1 M,3 M,1 T,4 S,1 M,4 T,1 D,1 D,1 T,1 M,4 T,1 L,3 R,1 T,4 S,1 F,3 R,4 F,3 T,3 F,1 R,1 R,3`

Using the table in `Figure 1`, we decode it to following plaintext:

`iamsorrymomihavegottogolivemymusic`

We have the plaintext but no idea what to do with it. Let's have a look at the `tune_700.mp3` file. Running `strings` command on it yields a [Google Drive link](https://drive.google.com/uc?export=download&id=1SR0Ztj6QpZlu39q28W0OBBDWJrDMTujB) that yields another pdf.

It's a password-protected PDF document. Perhaps the plaintext we obtained is the pdf's passcode? 

Let us give it a go.

![Figure 6](figure6.png)

And, voila! We have got the flag.