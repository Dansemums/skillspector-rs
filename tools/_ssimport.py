"""Makes `import skillspector.<module>` work on a bare checkout of SkillSpector.

Set SKILLSPECTOR_SRC to `<checkout>/src` (the checkout must be at the commit pinned in NOTICE) and run
with Python 3.13 (Unicode 15.1.0). The heavy LLM dependencies the package `__init__` imports are
replaced by stubs; the deterministic modules this repo ports do not need them. Without the variable
this is a no-op, so an installed `skillspector` package is used instead.
"""
import importlib.abc
import importlib.machinery
import importlib.metadata as _md
import os
import sys
from unittest.mock import MagicMock

_STUBBED = ("langchain_core", "langgraph", "langchain", "pydantic_settings", "langsmith")


class _Stub(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, name, path, target=None):
        if name.split(".")[0] in _STUBBED:
            return importlib.machinery.ModuleSpec(name, self, is_package=True)

    def create_module(self, spec):
        module = MagicMock()
        module.__path__ = []
        module.__spec__ = spec
        return module

    def exec_module(self, module):
        pass


def private_data(name, default_dir="private-data"):
    """Path of a file inside $SKILLSPECTOR_RS_PRIVATE_DATA (default ./private-data)."""
    return os.path.join(os.environ.get("SKILLSPECTOR_RS_PRIVATE_DATA", default_dir), name)


def setup():
    src = os.environ.get("SKILLSPECTOR_SRC")
    if not src:
        return
    version = _md.version
    _md.version = lambda n: "0" if n == "skillspector" else version(n)
    sys.meta_path.insert(0, _Stub())
    sys.path.insert(0, src)


setup()
