"""Keep a failing phase from hiding later CI coverage."""
import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize('timing', [False, True])
@pytest.mark.parametrize('failure', [False, True])
def test_all_phases_run_and_report_failures(monkeypatch, capsys, timing, failure):
    path = Path(__file__).resolve().parents[1] / 'scripts' / 'run_tests.py'
    spec = importlib.util.spec_from_file_location('supportproxy_test_runner', path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    calls = []

    def invoke(cmd, **kwargs):
        calls.append(cmd)
        if failure and 'tests/test_sysid32.py' in cmd:
            raise subprocess.CalledProcessError(1, cmd)
        return ''

    monkeypatch.setattr(runner, 'run', invoke)
    monkeypatch.setattr(runner, 'run_capture', invoke)
    monkeypatch.setattr(runner.os, 'chdir', lambda _: None)
    monkeypatch.setattr(runner.os.path, 'isfile', lambda _: True)
    monkeypatch.setattr(sys, 'argv', ['run_tests.py', '--no-build'] + (['--timing'] if timing else []))
    assert runner.main() == (1 if failure else 0)
    assert any('tests/test_sysid32.py' in cmd for cmd in calls)
    assert 'tests/webadmin/' in calls[-1]
    output = capsys.readouterr().out
    assert ('Failed phases: Robustness Tests' in output) == failure
    assert ('All tests completed.' in output) != failure
