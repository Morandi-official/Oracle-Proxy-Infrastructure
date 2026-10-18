"""No-IO ISO edition index rejection tests."""
import unittest
from choose_official_wim_edition import (
    EXPECTED_DISPLAY, ImageSelectionRefused, select_index,
)

def img(index=2, display=EXPECTED_DISPLAY, edition="ServerStandardEval", arch="9"):
    return (f'<IMAGE INDEX="{index}"><NAME>Windows Server 2025 SERVERSTANDARD</NAME>'
            f'<DISPLAYNAME>{display}</DISPLAYNAME>'
            f'<WINDOWS><EDITIONID>{edition}</EDITIONID><ARCH>{arch}</ARCH></WINDOWS>'
            '</IMAGE>')

def wim(*images):
    return ('<?xml version="1.0"?><WIM>'+''.join(images)+'</WIM>').encode("utf-16")

class R103WimEvalIndexTests(unittest.TestCase):
    def test_only_exact_eval_desktop_arch_image_index(self):
        self.assertEqual(select_index(wim(
            img(1, "Windows Server 2025 Standard Evaluation"),
            img(2),
            img(3,"Windows Server 2025 Datacenter Evaluation (Desktop Experience)",
                edition="ServerDatacenterEval"))),2)
    def test_utf16_bom_and_index_not_hardcoded_two(self):
        self.assertEqual(select_index(wim(img(1))),1)
    def test_denies_malformed_duplicate_or_unbounded_images(self):
        for sample in (
            b"", b"not-xml",
            wim(img(2),img(2)),wim(img(0)),wim(img(9)),
            wim(*[img(i,display="other") for i in range(1,9)]+[img(1)]),
        ):
            with self.subTest(sample_len=len(sample)),self.assertRaises(ImageSelectionRefused):
                select_index(sample)
    def test_denies_wrong_product_edition_arch(self):
        for entry in (
            img(2,display="Windows Server 2025 Standard"),
            img(2,edition="ServerDatacenterEval"),
            img(2,arch="0"),img(2,arch="12"),
        ):
            with self.assertRaises(ImageSelectionRefused):
                select_index(wim(entry))
    def test_denies_untrusted_types_or_oversized_values(self):
        for value in (None,"<WIM/>", b"a"*(1_048_576+1)):
            with self.assertRaises(ImageSelectionRefused):
                select_index(value)
    def test_denies_ambiguous_double_desktop_edition(self):
        with self.assertRaises(ImageSelectionRefused):
            select_index(wim(img(1),img(2)))

if __name__=="__main__":
    unittest.main()
