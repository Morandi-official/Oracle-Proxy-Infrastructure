"""Bounded static extraction of signed vendor NSIS/LZMA2 blocks; executes nothing.

Some NSIS forks use raw LZMA2, which the hosted 7-Zip NSIS handler does not
recognize. Original installer identity must be verified by the caller first.
Only intact PE blocks are retained, with generated filenames (no archive paths).
"""
import lzma
import struct
import sys
from pathlib import Path

MAGIC = b'\xef\xbe\xad\xdeNullsoftInst'
MAX_BLOCK = 300_000_000
MAX_TOTAL = 1_000_000_000


def blocks(data):
    candidates = []
    start = 0
    while True:
        at = data.find(MAGIC, start)
        if at < 0: break
        start = at + len(MAGIC)
        if at < 4 or at + 24 > len(data): continue
        flags, = struct.unpack_from('<I', data, at-4)
        header_size, total = struct.unpack_from('<II', data, at+16)
        if flags < 32 and 0 < header_size < 16_000_000 and 28 < total <= len(data)-(at-4):
            candidates.append((at-4, header_size, total))
    if len(candidates) != 1: raise ValueError('UNAMBIGUOUS_NSIS_HEADER_REQUIRED')
    start, expected_header, total = candidates[0]
    position = start + 28; end = start + total; expanded = 0; count = 0
    while position + 4 < end:
        descriptor, = struct.unpack_from('<I', data, position); position += 4
        size = descriptor & 0x7fffffff
        if size > MAX_BLOCK or position + size > end:
            raise ValueError('INVALID_BLOCK_LENGTH')
        body = data[position:position+size]; position += size
        if descriptor & 0x80000000:
            if size<2: raise ValueError('INVALID_COMPRESSED_LENGTH')
            prop = body[0]
            if prop > 40: raise ValueError('UNSUPPORTED_LZMA2_PROPERTY')
            dictionary = 0xffffffff if prop == 40 else (2 | (prop & 1)) << ((prop >> 1) + 11)
            if dictionary > 64 * 1024 * 1024: raise ValueError('LZMA2_DICTIONARY_LIMIT')
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
                                           filters=[{'id':lzma.FILTER_LZMA2,'dict_size':dictionary}])
            body = decoder.decompress(body[1:], max_length=MAX_BLOCK+1)
            if not decoder.eof or len(body)>MAX_BLOCK: raise ValueError('INCOMPLETE_OR_OVERSIZED_BLOCK')
        expanded += len(body); count += 1
        if expanded > MAX_TOTAL or count > 4096: raise ValueError('ARCHIVE_LIMIT')
        if count == 1:
            if len(body) != expected_header: raise ValueError('HEADER_SIZE_MISMATCH')
        else: yield count, body
    if end-position not in (0,4): raise ValueError('INVALID_ARCHIVE_TRAILER')


def main():
    source, destination = Path(sys.argv[1]), Path(sys.argv[2])
    if source.stat().st_size > 400_000_000: raise ValueError('INSTALLER_LIMIT')
    destination.mkdir(parents=True,exist_ok=False); count = 0
    for index, body in blocks(source.read_bytes()):
        if len(body)<128 or body[:2]!=b'MZ': continue
        offset, = struct.unpack_from('<I',body,0x3c)
        if offset+24>len(body) or body[offset:offset+4]!=b'PE\0\0': continue
        flags, = struct.unpack_from('<H',body,offset+22)
        suffix = '.dll' if flags & 0x2000 else '.exe'
        (destination/f'block-{index:04d}{suffix}').write_bytes(body); count+=1
    if not count: raise ValueError('NO_PE_PAYLOADS')
    print(f'STATIC_NSIS_LZMA2_PE_PAYLOADS={count}')


if __name__=='__main__': main()
