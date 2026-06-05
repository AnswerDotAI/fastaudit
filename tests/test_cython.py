import pyximport, sys
from pathlib import Path
from fastcore.test import expect_fail
from fastaudit.core import mk_audit


def test_cython_calls_are_audited():
    root = Path(__file__).parent
    moddir = root/'cython_src'
    sys.path.insert(0, str(moddir))
    pyximport.install(build_dir=str(root/'cython_build'), language_level=3)
    try:
        import cyprobe
        with mk_audit([root])():
            with expect_fail(PermissionError): cyprobe.add_one(1)
    finally: sys.path.remove(str(moddir))
