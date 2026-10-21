import importlib.util
import lzma
import struct
import unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('nsis',Path(__file__).with_name('extract_nsis_lzma2.py'))
nsis=importlib.util.module_from_spec(spec);spec.loader.exec_module(nsis)


def archive(contents):
    frames=[]
    for content in [b'Synthetic header',*contents]:
        compressed=b'\x10'+lzma.compress(content,format=lzma.FORMAT_RAW,filters=[{'id':lzma.FILTER_LZMA2,'dict_size':1<<20}])
        frames.append(struct.pack('<I',len(compressed)|0x80000000)+compressed)
    tail=b''.join(frames)+b'\0'*4
    return b'\0'*4+nsis.MAGIC+struct.pack('<II',16,28+len(tail))+tail


class StaticArchiveTests(unittest.TestCase):
    def test_raw_lzma2_streams_do_not_execute_or_trust_names(self):
        self.assertEqual(list(nsis.blocks(archive([b'../../never-a-path',b'MZsynthetic']))),[(2,b'../../never-a-path'),(3,b'MZsynthetic')])
    def test_truncation_and_missing_header_are_rejected(self):
        for value in [b'not-an-archive',archive([b'data'])[:-3]]:
            with self.assertRaises(ValueError):list(nsis.blocks(value))
    def test_attacker_controlled_dictionary_cannot_allocate_unbounded_memory(self):
        value=bytearray(archive([b'data']));value[32]=40
        with self.assertRaisesRegex(ValueError,'DICTIONARY_LIMIT'):list(nsis.blocks(value))
    def test_header_declared_length_must_match_actual_decoded_bytes(self):
        value=bytearray(archive([b'data']));struct.pack_into('<I',value,20,17)
        with self.assertRaisesRegex(ValueError,'HEADER_SIZE_MISMATCH'):list(nsis.blocks(value))


if __name__=='__main__':unittest.main()
