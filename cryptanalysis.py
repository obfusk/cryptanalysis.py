#!/usr/bin/python
# encoding: utf8

# --                                                            ; {{{1
#
# File        : cryptanalysis.py
# Maintainer  : Felix C. Stegerman <flx@obfusk.net>
# Date        : 2016-10-20
#
# Copyright   : Copyright (C) 2016  Felix C. Stegerman
# Version     : v0.0.3
# License     : GPLv3+
#
# --                                                            ; }}}1

                                                                # {{{1
r"""
Simple python (2+3) cryptanalysis tools

Examples
========

Simple monoalphabetic substitution ciphers
------------------------------------------

>>> "".join(sorted(simple_substitution_random_cipher())) == ALPHAS
True
>>> sorted(simple_substitution_random_cipher([1,4,2,3]))
[1, 2, 3, 4]

>>> simple_substitution_encrypt([1,2,1,3,2], [4,3,2,1], [1,2,3,4])
[4, 3, 4, 2, 3]

>>> cipher_alphabet = 'qmjztgfkpwlsboxncryevhiadu'
>>> plaintext       = 'fleeatoncewearediscovered'
>>> ciphertext      = simple_substitution_encrypt(plaintext, cipher_alphabet)
>>> ciphertext
'gsttqexojtitqrtzpyjxhtrtz'

>>> simple_substitution_decrypt(ciphertext, cipher_alphabet)
'fleeatoncewearediscovered'

>>> text = sanitize(slurp("/usr/share/common-licenses/GPL-3"))
>>> letter_frequency_table(text)
e : 0.11645
o : 0.09381
t : 0.08822
r : 0.07865
i : 0.07818
a : 0.06920
n : 0.06865
s : 0.06064
c : 0.04205
h : 0.03823
l : 0.03397
d : 0.03317
u : 0.02974
p : 0.02801
f : 0.02559
m : 0.02368
y : 0.02332
g : 0.01895
w : 0.01498
v : 0.01180
b : 0.01162
k : 0.00639
x : 0.00202
q : 0.00126
j : 0.00101
z : 0.00040
>>> letter_frequency_table([1,2,3,4,1,1,3,4,3], [1,2,3,4])
1 : 0.33333
3 : 0.33333
4 : 0.22222
2 : 0.11111


>>> ciphertext = '''vbpfaop qnvq csf ysoq xvbz vrsfq qnz bapnq qs
... ebadvxc rzxvftz csf nvdz osqnaop qs nayz at os yakkzbzoq qnvo
... tvcaop csf ysoq xvbz vrsfq kbzz tezzxn rzxvftz csf nvdz osqnaop qs
... tvc'''.replace('\n', ' ')
>>> known = dict(["qt","nh","ze","va","br","so","dv",
...               "ai","pg","yd","on","ts","cy","fu",
...               "rb","xc","ep","kf"]) # iterative process
>>> pt, gu, t = break_simple_substitution(ciphertext, FREQS, known)
>>> for a,b,c,d in gu:
...   print("{} ({:5d}) ~ {} ({:5d})".format(a,c,b,d))
z ( 8989) ~ e (12702)
q ( 8427) ~ t ( 9056)
v ( 7865) ~ a ( 8167)
s ( 7865) ~ o ( 7507)
o ( 6180) ~ n ( 6749)
n ( 5618) ~ h ( 6094)
a ( 5056) ~ i ( 6966)
f ( 5056) ~ u ( 2758)
b ( 3933) ~ r ( 5987)
c ( 3933) ~ y ( 1974)
t ( 3371) ~ s ( 6327)
x ( 3371) ~ c ( 2782)
p ( 3371) ~ g ( 2015)
y ( 2247) ~ d ( 4253)
r ( 2247) ~ b ( 1492)
k ( 1685) ~ f ( 2228)
d ( 1685) ~ v (  978)
e ( 1124) ~ p ( 1929)
g (    0) ~ l ( 4025)
h (    0) ~ m ( 2406)
i (    0) ~ w ( 2360)
j (    0) ~ k (  772)
l (    0) ~ j (  153)
m (    0) ~ x (  150)
u (    0) ~ q (   95)
w (    0) ~ z (   74)
>>> for w in pt.split(): print(w)
arguing
that
you
dont
care
about
the
right
to
privacy
because
you
have
nothing
to
hide
is
no
different
than
saying
you
dont
care
about
free
speech
because
you
have
nothing
to
say

# - Snowden


Columnar transposition cipher
-----------------------------

>>> plaintext = sanitize("WE ARE DISCOVERED. FLEE AT ONCE")
>>> plaintext
'wearediscoveredfleeatonce'
>>> ciphertext = columnar_transposition_encrypt(plaintext, "zebras")
>>> ciphertext
'evlnxacdtxeseaxrofoxdeecxwiree'

>>> xs = list(columnar_transposition_decrypt(ciphertext, 5))
>>> len(xs)
720
>>> len([ x for x in xs if x[-5:] == "xxxxx" ])
120
>>> (plaintext + 'xxxxx') in xs
True


Rail fence cipher
-----------------

>>> rail_fence_encrypt([1,2,3,4,5,6,7,8], 3)
[1, 5, 2, 4, 6, 8, 3, 7]

>>> plaintext = sanitize("WE ARE DISCOVERED. FLEE AT ONCE")
>>> plaintext
'wearediscoveredfleeatonce'
>>> ciphertext = rail_fence_encrypt(plaintext, 3)
>>> ciphertext
'wecrlteerdsoeefeaocaivden'
>>> for i in xrange(2, 6): rail_fence_decrypt(ciphertext, i)
'weefceralotceaeirvddseone'
'wearediscoveredfleeatonce'
'wtevfeeeedarcdoecsroaniel'
'wlsadooteeeceaeecrfinvedr'


Vigenère cipher
---------------

>>> plaintext   = "attackatdawn"
>>> key         = "lemon"
>>> ciphertext  = vinegere_encrypt(plaintext, key)
>>> ciphertext
'lxfopvefrnhr'
>>> vinegere_decrypt(ciphertext, key)
'attackatdawn'


Linear-feedback shift register
------------------------------

>>> state, taps = [0,1,1,1,1,0,1,1], [0,3,4]
>>> for bit, state_ in itertools.islice(lfsr(state, taps), 5):
...   print(bit, state_)
0 [1, 1, 1, 1, 0, 1, 1, 0]
1 [1, 1, 1, 0, 1, 1, 0, 0]
1 [1, 1, 0, 1, 1, 0, 0, 0]
1 [1, 0, 1, 1, 0, 0, 0, 1]
1 [0, 1, 1, 0, 0, 0, 1, 0]


Block Ciphers
-------------

>>> k           = 0b101
>>> plaintext   = [0b011, 0b111, 0b101, 0b001]
>>> ciphertext  = ECB(plaintext, k)
>>> bs(ciphertext)
['100', '011', '001', '010']
>>> for x, (y, z) in zip(plaintext, ECB_int(plaintext, k)):
...   print("C({}, {}) = {} (w/ x ^ k = {})".format(*bs([x, k, z, y])))
C(011, 101) = 100 (w/ x ^ k = 110)
C(111, 101) = 011 (w/ x ^ k = 010)
C(101, 101) = 001 (w/ x ^ k = 000)
C(001, 101) = 010 (w/ x ^ k = 100)

>>> list(ECB_inv(ECB(plaintext, k), k)) == plaintext
True

>>> iv          = 0b111
>>> ciphertext  = CBC(plaintext, k, iv)
>>> bs(ciphertext)
['000', '011', '110', '011']
>>> for x, (y, z) in zip(plaintext, CBC_int(plaintext, k, iv)):
...   print("C({}, {}) = {} (w/ x ^ z = {})".format(*bs([x, k, z, y])))
C(011, 101) = 000 (w/ x ^ z = 100)
C(111, 101) = 011 (w/ x ^ z = 111)
C(101, 101) = 110 (w/ x ^ z = 110)
C(001, 101) = 011 (w/ x ^ z = 111)

>>> list(CBC_inv(CBC(plaintext, k, iv), k, iv)) == plaintext
True

>>> bin_(CBC_MAC(plaintext, k, iv))
'011'
>>> m0 = C_inv(iv, k) ^ iv
>>> bin_(m0)
'111'
>>> bin_(CBC_MAC([m0] + plaintext, k, iv))
'011'

>>> import random
>>> ok = 0
>>> for x in xrange(1000):
...   k   = random.randint(0b000, 0b111)
...   iv  = random.randint(0b000, 0b111)
...   m   = [0b111, 0b100, 0b101]
...   t   = CBC_MAC(m, k, iv)
...   m1  = [0b011, 0b111, 0b101, 0b001]
...   t1  = CBC_MAC(m1, k, iv)
...   m2  = m + [t ^ m1[0] ^ iv] + m1[1:]
...   t2  = CBC_MAC(m2, k, iv)
...   if t1 == t2: ok += 1
>>> ok
1000

>>> k           = 0b100
>>> iv          = 0b010
>>> alice_ct    = [0b111, 0b100, 0b101]
>>> bob_ct      = [0b110, 0b100, 0b101]
>>> third_ct    = [0b011, 0b100, 0b101]
>>> alice_pt    = list(CBC_inv(alice_ct, k, iv))
>>> bob_pt      = list(CBC_inv(bob_ct, k, iv))
>>> third_pt    = list(CBC_inv(third_ct, k, iv))
>>> bs(alice_pt)
['011', '101', '111']
>>> bs(bob_pt)
['101', '100', '111']
>>> bs(third_pt)
['100', '001', '111']
>>> hamming_distance("".join(bs(alice_pt)), "".join(bs(bob_pt)))
3
>>> hamming_distance("".join(bs(alice_pt)), "".join(bs(third_pt)))
4

>>> from itertools import islice
>>> k           = 0b101
>>> iv          = 0b100
>>> bs(islice(CTR_stream(k, iv), 3))
['000', '001', '110']
>>> for x, y in islice(CTR_stream_int(k, iv), 3):
...   print("{} (w/ ctr = {})".format(*bs([y, x])))
000 (w/ ctr = 100)
001 (w/ ctr = 101)
110 (w/ ctr = 110)

>>> plaintext   = [0b001, 0b110, 0b111]
>>> ciphertext  = CTR_inv(plaintext, k, iv)
>>> bs(ciphertext)
['001', '111', '001']
>>> for x, y, z, xor in CTR_inv_int(plaintext, k, iv):
...   print("{} ^ {} = {} (w/ ctr = {})".format(*bs([x, z, xor, y])))
001 ^ 000 = 001 (w/ ctr = 100)
110 ^ 001 = 111 (w/ ctr = 101)
111 ^ 110 = 001 (w/ ctr = 110)

>>> p1  = [0b010, 0b110, 0b110]
>>> c1  = [0b110, 0b001, 0b101]
>>> c2  = [0b101, 0b011, 0b111]
>>> ks  = [ p ^ c for p,c in zip(p1, c1) ]
>>> bs(ks)
['100', '111', '011']
>>> p2  = [ c ^ k for c,k in zip(c2, ks) ]
>>> bs(p2)
['001', '100', '100']

>>> [ p ^ k for p,k in zip(p1, ks) ] == c1
True
>>> [ p ^ k for p,k in zip(p2, ks) ] == c2
True

>>> list(CTR_inv(CTR(plaintext, k, iv), k, iv)) == plaintext
True


Helper functions
----------------

>>> sanitize("Flee at once. We are discovered!")
'fleeatoncewearediscovered'

>>> f = slurp(__file__).split("\n")
>>> f[0], f[-2]
('#!/usr/bin/python', '# vim: set tw=70 sw=2 sts=2 et fdm=marker :')

>>> string_if(['f','o','o'], "bar")
'foo'
>>> string_if([1,2,3], [4,5])
[1, 2, 3]


Links
=====

https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
https://en.wikipedia.org/wiki/Hamming_distance
https://en.wikipedia.org/wiki/Letter_frequency
https://en.wikipedia.org/wiki/Linear-feedback_shift_register
https://en.wikipedia.org/wiki/Substitution_cipher
https://en.wikipedia.org/wiki/Transposition_cipher
https://en.wikipedia.org/wiki/Transposition_cipher#Columnar_transposition
https://en.wikipedia.org/wiki/Transposition_cipher#Rail_Fence_cipher
https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher
"""
                                                                # }}}1

from __future__ import print_function

import argparse, functools, itertools, math, random, sys

if sys.version_info.major == 2:                                 # {{{1
  izip    = itertools.izip
else:
  xrange  = range
  izip    = zip
  reduce  = functools.reduce
                                                                # }}}1

__version__       = "0.0.3"


def main(*args):                                                # {{{1
  p = _argument_parser(); n = p.parse_args(args)
  import doctest
  failures, tests = doctest.testmod(verbose = n.verbose)
  return 0 if failures == 0 else 1
                                                                # }}}1

def _argument_parser():                                         # {{{1
  p = argparse.ArgumentParser(description = "cryptanalysis")
  p.add_argument("--version", action = "version",
                 version = "%(prog)s {}".format(__version__))
  p.add_argument("--verbose", "-v", action = "store_true",
                 help = "run tests verbosely")
  return p
                                                                # }}}1


def simple_substitution_random_cipher(alphabet = None):
  """Creates a pseudorandom simple monoalphabetic substitution
  cipher."""
  if alphabet is None: alphabet = ALPHAS
  alphas = list(alphabet); random.shuffle(alphas)
  return string_if(alphas, alphabet)

def simple_substitution_encrypt(plaintext, cipher_alphabet,
                                alphabet = None):
  """Encrypts a plaintext using a simple monoalphabetic substitution
  cipher and returns the resulting ciphertext."""
  if alphabet is None: alphabet = ALPHAS
  mapping = dict(izip(alphabet, cipher_alphabet))
  return string_if([ mapping[c] for c in plaintext ], plaintext)

def simple_substitution_decrypt(ciphertext, cipher_alphabet,
                                alphabet = None):
  """Decrypts a ciphertext using a simple monoalphabetic substitution
  cipher and returns the resulting plaintext."""
  if alphabet is None: alphabet = ALPHAS
  return simple_substitution_encrypt(ciphertext, alphabet,
                                     cipher_alphabet)


FREQ_PRECISION = 5

def letter_frequency_dict(text, alphabet = None,                # {{{1
                          precision = FREQ_PRECISION):
  """Calculates letter frequencies."""
  if alphabet is None: alphabet = ALPHAS
  freqs = dict(izip(alphabet, [0]*len(alphabet))); n = float(len(text))
  if not text: return freqs
  for c in text:
    if c in alphabet: freqs[c] += 1
  for k in freqs: freqs[k] = int(round(10**precision*freqs[k]/n))
  return freqs
                                                                # }}}1

def letter_frequency_list(text, alphabet = None,
                          precision = FREQ_PRECISION):
  """Letter frequencies as (always identically) sorted list."""
  return letter_frequency_sort(letter_frequency_dict(text, alphabet,
                                                     precision))

def letter_frequency_sort(freqs):
  """Sorted frequency dict as list of pairs."""
  return sorted(freqs.items(), key = lambda x: (-x[1], x[0]))

def letter_frequency_table(text, alphabet = None,
                           precision = FREQ_PRECISION):
  """Tabulates letter frequencies."""
  fmt   = "{} : 0.{:0%dd}" % precision
  freqs = letter_frequency_list(text, alphabet, precision)
  for k, v in freqs: print(fmt.format(k, v))


# TODO
def break_simple_substitution(ciphertext, reference_freqs,      # {{{1
                              known = {}):
  """Try to break simple substitution cipher by matching using letter
  frequencies."""
  f               = lambda x, y: ( (k,v) for k,v in x if k not in y )
  g               = lambda c, x: x.upper() if c not in known else x
  ct_             = sanitize(ciphertext, keep = " ")
  freqs           = letter_frequency_dict(ct_)
  freqs_          = f(letter_frequency_sort(freqs), known.keys())
  reffreqs_       = f(letter_frequency_sort(reference_freqs),
                                            known.values())
  guesses, tbl    = [], dict(known)
  for k,v in known.items():
    guesses.append((k,v,freqs[k],reference_freqs[v]))
  for a,b in izip(freqs_, reffreqs_):
    tbl[a[0]] = b[0]; guesses.append((a[0],b[0],a[1],b[1]))
  guesses.sort(key = lambda x: (-x[2], -x[3], x[0], x[1]))
  ptext_guess     = ( g(c, tbl[c]) if c != ' ' else c for c in ct_ )
  return (string_if(ptext_guess, ciphertext), guesses, tbl)
                                                                # }}}1


def columnar_transposition_encrypt(plaintext, keyword,          # {{{1
                                   null = 'x'):
  """Encrypts a plaintext using a columnar transposition cipher and
  returns the resulting ciphertext."""
  n, xs       = len(keyword), [ ALPHAS.index(c) for c in keyword ]
  m           = math.ceil(len(plaintext)/float(n))
  colidxs     = [ j for i,j in sorted(izip(xs, xrange(n))) ]
  columns     = [ [] for i in xrange(n) ]; i = 0
  for c in plaintext: columns[i].append(c); i = (i + 1) % n
  for c in columns:
    if len(c) < m: c.append(null)
  ciphertext  = [ c for i in colidxs for c in columns[i] ]
  return string_if(ciphertext, plaintext)
                                                                # }}}1

def columnar_transposition_decrypt(ciphertext, col_len):        # {{{1
  """Decrypts a ciphertext using a columnar transposition cipher and
  returns the resulting plaintext."""
  cols    = len(ciphertext) // col_len
  columns = list(map(list, izip(*([iter(ciphertext)]*col_len))))
  for p in itertools.permutations(xrange(cols)):
    plaintext = []
    for i in xrange(col_len):
      for j in p: plaintext.append(columns[j][i])
    yield string_if(plaintext, ciphertext)
                                                                # }}}1


def rail_fence_encrypt(plaintext, n):                           # {{{1
  """Encrypts a plaintext using a rail fence cipher and returns the
  resulting ciphertext."""
  if n <= 1: raise ValueError("n must be > 1")
  rails = [ [] for i in xrange(n) ]; i = 0; d = 1
  for c in plaintext:
    rails[i].append(c)
    if   i == n-1: d = -1
    elif i ==   0: d =  1
    i += d
  return string_if([ x for xs in rails for x in xs ], plaintext)
                                                                # }}}1

def rail_fence_decrypt(ciphertext, n):
  """Decrypts a ciphertext using a rail fence cipher and returns the
  resulting plaintext."""
  encryption = rail_fence_encrypt(xrange(len(ciphertext)), n)
  decryption = [None]*len(ciphertext)
  for i, j in enumerate(encryption): decryption[j] = i
  return string_if([ ciphertext[i] for i in decryption ], ciphertext)


def vinegere_encrypt(plaintext, key):
  """Encrypts a plaintext using a Vigenère cipher and return the
  resulting ciphertext."""
  plaintext = sanitize(plaintext); key = sanitize(key); a = ord('a')
  return "".join( chr(a + ((ord(m)-a + ord(k)-a) % 26))
                  for m, k in izip(plaintext, itertools.cycle(key)) )

def vinegere_decrypt(ciphertext, key):
  """Decrypts a ciphertext using a Vigenère cipher and return the
  resulting plaintext."""
  ciphertext = sanitize(ciphertext); key = sanitize(key); a = ord('a')
  return "".join( chr(a + ((ord(m) - ord(k)) % 26))
                  for m, k in izip(ciphertext, itertools.cycle(key)) )


def lfsr(state, taps):
  """Linear-feedback shift register."""
  while True:
    newbit          = reduce(lambda x, y: x ^ state[y], taps, 0)
    oldbit, state   = state[0], state[1:] + [newbit]
    yield oldbit, state


def ECB_int(xs, k): return ( C_int(x, k) for x in xs )
def ECB(xs, k): return ( y[-1] for y in ECB_int(xs, k) )

def ECB_inv_int(ys, k): return ( C_inv_int(y, k) for y in ys )
def ECB_inv(ys, k): return ( x[-1] for x in ECB_inv_int(ys, k) )

def CBC_int(xs, k, iv):
  z = iv
  for x in xs:
    y = x ^ z; z = C(y, k); yield y, z

def CBC(xs, k, iv): return ( y[-1] for y in CBC_int(xs, k, iv) )

def CBC_inv_int(ys, k, iv):
  z = iv
  for y in ys:
    t = C_inv(y, k); x = t ^ z; z = y; yield t, x

def CBC_inv(ys, k, iv): return ( x[-1] for x in CBC_inv_int(ys, k, iv) )

def CBC_MAC(xs, k, iv):
  mac = 0
  for y in CBC(xs, k, iv): mac = y
  return mac

def CTR_stream_int(k, iv, n = 3):
  while True:
    yield iv, C(iv, k); iv = (iv + 1) % 2**n

def CTR_stream(k, iv, n = 3): return ( y[-1] for y in CTR_stream_int(k, iv, n) )

def CTR_int(xs, k, iv, n = 3):
  for x, (y, z) in izip(xs, CTR_stream_int(k, iv, n)):
    yield x, y, z, x ^ z

def CTR(xs, k, iv, n = 3): return ( y[-1] for y in CTR_int(xs, k, iv, n) )

CTR_inv_int, CTR_inv = CTR_int, CTR

def C_int(x, k): return x ^ k, S[x ^ k]
def C_inv_int(y, k): return S_inv[y], S_inv[y] ^ k

def C(x, k): return C_int(x, k)[-1]
def C_inv(y, k): return C_inv_int(y, k)[-1]

S = {                                                           # {{{1
  0b000: 0b001,
  0b001: 0b000,
  0b010: 0b011,
  0b011: 0b110,
  0b100: 0b010,
  0b101: 0b111,
  0b110: 0b100,
  0b111: 0b101,
}                                                               # }}}1

S_inv = dict( (v,k) for k,v in S.items() )


def bin_(x, n = 3): return ("0"*n + bin(x)[2:])[-n:]
def bs(xs, n = 3): return [ bin_(x, n) for x in xs ]

def hamming_distance(xs, ys):
  n = 0
  for x, y in zip(xs, ys):
    if x != y: n += 1
  return n


def sanitize(plaintext, keep = []):
  """Returns sanitized plaintext; i.e. alphabetic characters only, all
  in lowercase."""
  return "".join( c.lower() for c in plaintext
                  if c.lower() in ALPHAS or c.lower() in keep )

def slurp(filename):
  """Returns all data in file as string."""
  with open(filename) as f: return f.read()

def string_if(x, y):
  """Returns the sequence x as string if y is one, else x."""
  return "".join(x) if isinstance(y, str) else x

ALPHAS  = "abcdefghijklmnopqrstuvwxyz"
FREQS   = dict([                                                # {{{1
  ('e', 12702), ('t',  9056), ('a',  8167), ('o',  7507),
  ('i',  6966), ('n',  6749), ('s',  6327), ('h',  6094),
  ('r',  5987), ('d',  4253), ('l',  4025), ('c',  2782),
  ('u',  2758), ('m',  2406), ('w',  2360), ('f',  2228),
  ('g',  2015), ('y',  1974), ('p',  1929), ('b',  1492),
  ('v',   978), ('k',   772), ('j',   153), ('x',   150),
  ('q',    95), ('z',    74)
])                                                              # }}}1

if __name__ == "__main__":
  sys.exit(main(*sys.argv[1:]))

# vim: set tw=70 sw=2 sts=2 et fdm=marker :
