"""Verify exact dependency source bytes before loading their modules."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
DEPS = Path(os.environ.get("OBSESSION_DEPS_ROOT", ROOT.parent / "obsession-deps")).resolve()
LOCK = json.loads((ROOT / "dependency-lock.json").read_text(encoding="utf-8"))


def verify_dependencies():
    for name, subject in LOCK.items():
        base = DEPS / ("pre-active" if name == "pre_active" else "obsession")
        for item in subject["files"]:
            path = (base / item["path"]).resolve()
            if not path.is_relative_to(base.resolve()):
                raise RuntimeError("dependency path escaped root")
            data = path.read_bytes()
            actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            if actual != item["sha"]:
                raise RuntimeError("pinned dependency bytes differ: " + item["path"])
    source = (DEPS / "pre-active" / "src").resolve()
    already = sys.modules.get("pre_active")
    if already is not None and not Path(already.__file__).resolve().is_relative_to(source):
        raise RuntimeError("unverified Pre-Active module was loaded earlier")
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))
    return {name: subject["head"] for name, subject in LOCK.items()}


PROVENANCE = verify_dependencies()
_name = "resident_initiative._pinned_goal_focus"
_spec = importlib.util.spec_from_file_location(_name, DEPS / "obsession" / "obsession_lab" / "goal_focus.py")
_module = importlib.util.module_from_spec(_spec)
sys.modules[_name] = _module
_spec.loader.exec_module(_module)
GoalFocus, GoalSpec, GoalSignal = _module.GoalFocus, _module.GoalSpec, _module.GoalSignal
