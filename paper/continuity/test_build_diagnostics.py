"""Regression checks for the final TeX and BibTeX log gate."""
from hashlib import sha256
from io import BytesIO, StringIO
from pathlib import Path
import runpy
import subprocess
from tempfile import TemporaryDirectory
import unittest


checker = runpy.run_path(str(Path(__file__).with_name('check_build.py')))
log_failures = checker['log_failures']


class BuildDiagnosticsTests(unittest.TestCase):
    def test_reports_each_warning_with_its_source(self):
        with TemporaryDirectory() as directory:
            tex = Path(directory) / 'paper.log'
            bib = Path(directory) / 'paper.blg'
            messages = [
                'Package hyperref Warning: Difference (2) between bookmark levels',
                r'Underfull \vbox (badness 10000) has occurred while \output is active',
                r'Overfull \hbox (2.0pt too wide) in paragraph at lines 10--12',
                'LaTeX Font Warning: Some font shapes were not available',
                'pdfTeX warning (dest): referenced destination does not exist',
                'Missing character: There is no character in this font!',
            ]
            tex.write_text('\n'.join(messages))
            bib.write_text('The style file: joc-basic.bst\nWarning--empty year in entry\n')
            expected = [f'{tex}:{i}: {message}' for i, message in enumerate(messages, 1)]
            expected.append(f'{bib}:2: Warning--empty year in entry')
            self.assertEqual(log_failures([tex, bib]), expected)

    def test_clean_logs_and_missing_evidence(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'paper.log'
            with self.assertRaises(FileNotFoundError):
                log_failures([path])
            path.touch()
            self.assertEqual(log_failures([path]), [f'{path}: empty compiler log'])
            path.write_text('Package rerunfilecheck Info: File unchanged.\n'
                            'Output written on paper.pdf (122 pages).\n')
            self.assertEqual(log_failures([path]), [])

    def test_formula_text_from_legacy_math_fonts(self):
        self.assertEqual(checker['math_inventory']('∑ aᵢ\nx ↦ y\n⋃ Aᵢ'), {'∑': 1, '↦': 1, '⋃': 1})
        self.assertEqual(checker['math_inventory']('X aᵢ\nx 7 y\nS Aᵢ'), {})
        self.assertEqual(checker['extraction_failures']('∑ aᵢ\n\f', 'test.pdf'), [])
        self.assertEqual(checker['extraction_failures']('\x01x\ufffd', 'test.pdf'),
                         ['test.pdf: invalid extracted character U+0001',
                          'test.pdf: invalid extracted character U+FFFD'])

    def test_log_label_is_display_only(self):
        label = 'review.log'
        message = 'Package hyperref Warning: invalid bookmark depth'
        self.assertEqual(checker['check_log'](StringIO(message), label),
                         [f'{label}:1: {message}'])

    def test_reviewed_pdf_digest_identifies_the_extracted_stream(self):
        pdf = Path(__file__).with_name('continuity.pdf').read_bytes()
        text, digest = checker['read_reviewed_pdf'](BytesIO(pdf))
        self.assertEqual(digest, sha256(pdf).hexdigest())
        self.assertIn('∑', text)
        with self.assertRaises(subprocess.CalledProcessError):
            checker['read_reviewed_pdf'](BytesIO(b'incomplete PDF'))


if __name__ == '__main__':
    unittest.main()
