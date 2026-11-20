"""Regression checks for the final TeX and BibTeX log gate."""
from pathlib import Path
import runpy
from tempfile import TemporaryDirectory
import unittest


log_failures = runpy.run_path(str(Path(__file__).with_name('check_build.py')))['log_failures']


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


if __name__ == '__main__':
    unittest.main()
