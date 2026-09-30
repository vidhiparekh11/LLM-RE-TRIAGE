import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NEEDS_TOOLCHAIN = not (shutil.which("gcc") and shutil.which("strip") and (shutil.which("r2") or shutil.which("radare2")))
requires_r2 = pytest.mark.skipif(NEEDS_TOOLCHAIN, reason="needs gcc, strip and radare2")


@pytest.fixture(scope="session")
def demo_binary(tmp_path_factory):
    if NEEDS_TOOLCHAIN:
        pytest.skip("needs gcc, strip and radare2")
    out = str(tmp_path_factory.mktemp("demo") / "demo_target")
    subprocess.run(["bash", os.path.join(ROOT, "examples", "build_demo.sh"), out], check=True, capture_output=True)
    return out


@pytest.fixture()
def backend(demo_binary):
    from retriage.backend import R2Backend
    b = R2Backend(demo_binary)
    yield b
    b.close()


@pytest.fixture()
def toolbox(backend):
    from retriage.tools import ToolBox
    return ToolBox(backend)


def valid_submission(**over):
    sub = {"verdict": {"classification": "unknown", "confidence": "low", "risk": "unrated"}, "summary": "test summary",
           "behaviors": [], "iocs": [], "obfuscation": [], "limitations": ["test limitation"], "recommendations": []}
    sub.update(over)
    return sub
