#!/usr/bin/env python
# -*- coding: latin-1 -*-

# <-- removing this magic comment breaks Python 3.4 on Windows
import binascii  # binascii is required for Python 3
import sys

# hexdump code from https://raw.githubusercontent.com/smorin/hextool/master/hexdump.py
# --- constants
PY3K = sys.version_info >= (3, 0)
# --- - chunking helpers
def chunks(seq, size):
  '''Generator that cuts sequence (bytes, memoryview, etc.)
     into chunks of given size. If `seq` length is not multiply
     of `size`, the lengh of the last chunk returned will be
     less than requested.

     >>> list( chunks([1,2,3,4,5,6,7], 3) )
     [[1, 2, 3], [4, 5, 6], [7]]
  '''
  d, m = divmod(len(seq), size)
  for i in range(d):
    yield seq[i*size:(i+1)*size]
  if m:
    yield seq[d*size:]

def chunkread(f, size):
  '''Generator that reads from file like object. May return less
     data than requested on the last read.'''
  c = f.read(size)
  while len(c):
    yield c
    c = f.read(size)

def genchunks(mixed, size):
  '''Generator to chunk binary sequences or file like objects.
     The size of the last chunk returned may be less than
     requested.'''
  if hasattr(mixed, 'read'):
    return chunkread(mixed, size)
  else:
    return chunks(mixed, size)
# --- - /chunking helpers

def dump(binary, size=2, sep=' '):
  '''
  Convert binary data (bytes in Python 3 and str in
  Python 2) to hex string like '00 DE AD BE EF'.
  `size` argument specifies length of text chunks
  and `sep` sets chunk separator.
  '''
  hexstr = binascii.hexlify(binary)
  if PY3K:
    hexstr = hexstr.decode('ascii')
  return sep.join(chunks(hexstr.upper(), size))

def dumpgen(data):
  '''
  Generator that produces strings:

  '00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................'
  '''
  generator = genchunks(data, 16)
  for addr, d in enumerate(generator):
    # 00000000:
    line = '%08X: ' % (addr*16)
    # 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 
    dumpstr = dump(d)
    line += dumpstr[:8*3]
    if len(d) > 8:  # insert separator if needed
      line += ' ' + dumpstr[8*3:]
    # calculate indentation, which may be different for the last line
    pad = 2
    if len(d) < 16:
      pad += 3*(16 - len(d))
    if len(d) <= 8:
      pad += 1
    line += ' '*pad

    for byte in d:
      # printable ASCII range 0x20 to 0x7E
      if not PY3K:
        byte = ord(byte)
      if 0x20 <= byte <= 0x7E:
        line += chr(byte)
      else:
        line += '.'
    yield line
  
def hexdump(data):
    gen = dumpgen(data)
    return '\n'.join(gen)
