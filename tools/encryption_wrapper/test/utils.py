import os
import sys
from importlib.util import spec_from_file_location, module_from_spec


def run_script(monkeypatch, command: str):
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
    command_words = command.split()
    script_path = os.path.join(project_root, command_words.pop(0))
    script_name = script_path.split("/")[-1]

    monkeypatch.setattr(sys, 'argv', [script_name, *command_words])
    spec = spec_from_file_location("__main__", script_path)
    spec.loader.exec_module(module_from_spec(spec))
