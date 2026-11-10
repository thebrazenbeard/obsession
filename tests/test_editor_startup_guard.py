"""Offline source-contract checks against editor-triggered code execution.

No editor, shell task, font, or repository asset is executed by these tests.
Set OBSESSION_EDITOR_SOURCE_ROOT to the checkout being qualified.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import unittest


ROOT = Path(os.environ.get(
    "OBSESSION_EDITOR_SOURCE_ROOT", Path(__file__).resolve().parents[1]
)).resolve()


def editor_json(name: str) -> dict:
    path = ROOT / ".vscode" / name
    # The repository need not ship any editor configuration. Absence is safe;
    # a present but malformed file is not silently treated as empty.
    if not path.exists():
        return {}
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"{name}: JSON object required")
    return value


class NoEditorTriggeredExecution(unittest.TestCase):
    def test_no_automatic_task_or_hidden_shell_task(self):
        tasks = editor_json("tasks.json").get("tasks", [])
        self.assertIsInstance(tasks, list)
        for i, task in enumerate(tasks):
            with self.subTest(index=i):
                self.assertIsInstance(task, dict)
                run_options = task.get("runOptions", {})
                self.assertNotEqual(
                    run_options.get("runOn"), "folderOpen",
                    "editor-open task execution is not an authorized entry point",
                )
                self.assertFalse(
                    task.get("hide", False),
                    "hidden editor tasks bypass normal source review",
                )
        settings = editor_json("settings.json")
        self.assertIsNot(
            settings.get("task.allowAutomaticTasks"), True,
            "workspace settings must not authorize automatic task execution",
        )
        nested = settings.get("tasks", {})
        self.assertNotEqual(
            nested.get("runOn") if isinstance(nested, dict) else None,
            "folderOpen",
            "workspace settings must not introduce an implicit shell entry point",
        )

    def test_no_script_interpreter_uses_a_font_path(self):
        tasks = editor_json("tasks.json").get("tasks", [])
        for i, task in enumerate(tasks):
            if not isinstance(task, dict):
                continue
            args = task.get("args", [])
            joined = " ".join([str(task.get("command", ""))] + list(map(str, args if isinstance(args, list) else [args])))
            with self.subTest(index=i):
                self.assertFalse(
                    re.search(r"(?i)\b(?:node|python(?:3)?|bash|pwsh|powershell)\b.*(?:public[/\\]fonts[/\\]|\.(?:ttf|otf|woff2?)\b)", joined),
                    "font assets are not executable scripts",
                )

    def test_font_assets_have_matching_magic(self):
        directory = ROOT / "public" / "fonts"
        if not directory.exists():
            return
        allowed = {
            ".ttf": {b"\x00\x01\x00\x00", b"true"},
            ".otf": {b"OTTO"},
            ".woff": {b"wOFF"},
            ".woff2": {b"wOF2"},
        }
        for item in directory.iterdir():
            if item.suffix.lower() not in allowed:
                continue
            with self.subTest(font=item.name):
                with item.open("rb") as stream:
                    header = stream.read(4)
                self.assertIn(header, allowed[item.suffix.lower()], "font extension/header mismatch")


if __name__ == "__main__":
    unittest.main()
