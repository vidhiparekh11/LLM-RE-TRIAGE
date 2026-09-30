import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))


def test_tools_doc_is_up_to_date():
    import gen_docs
    assert open(os.path.join(ROOT, "docs", "tools.md"), encoding="utf-8").read() == gen_docs.tools_markdown()


def test_public_hygiene_check_passes():
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "check_public.py")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


def test_hygiene_check_catches_problems(tmp_path):
    import shutil
    work = tmp_path / "repo"
    shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.egg-info", ".pytest_cache"))
    (work / "leak.txt").write_text("key=" + "sk-" + "abcdefghijklmnopqrstuvwxyz0123")
    (work / "sample.bin").write_bytes(b"\x7f" + b"ELF" + b"\x00" * 64)
    r = subprocess.run([sys.executable, str(work / "scripts" / "check_public.py")], capture_output=True, text=True)
    assert r.returncode == 1 and "sk-" in r.stdout and "ELF" in r.stdout
