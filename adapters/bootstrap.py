"""Real import of the vendored microsoft/AIOpsLab package's action and
parser classes, bypassing an unrelated heavy import cascade.

`aiopslab/orchestrator/__init__.py` does `from .orchestrator import
Orchestrator`, which transitively imports the problems/tasks/evaluators
tree -- including a module-level `tiktoken.encoding_for_model(...)` call
in `aiopslab/orchestrator/evaluators/quantitative.py` that fetches a BPE
file over the network the first time it runs. None of that is needed to
reach `aiopslab.orchestrator.actions.base.TaskActions` or
`aiopslab.orchestrator.parser.ResponseParser`, the two classes WITNESS
actually hooks into.

This module registers `aiopslab.orchestrator` in `sys.modules` as a bare
package object *before* importing the leaf modules, with its `__path__`
pointed at the real on-disk `aiopslab/orchestrator/` directory. Python's
import machinery then sees the package as already loaded (skipping its
real `__init__.py`, and with it the heavy cascade) while still resolving
real submodules -- `.actions.base`, `.parser` -- normally from disk. This
is a real import of AIOpsLab's actual code -- not a stand-in -- it just
skips loading parts of the framework that are irrelevant to action
execution and, in a network-restricted environment, would otherwise fail
the import for a reason that has nothing to do with WITNESS's
integration point.

In an environment with unrestricted network access (any normal AIOpsLab
deployment), `import_real_aiopslab` still works identically; the stub is
harmless because nothing WITNESS calls ever needs the real
`Orchestrator`, `ProblemRegistry`, or evaluator classes -- only
`TaskActions`, `ResponseParser`, and `Shell`.
"""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path


class AIOpsLabNotFoundError(RuntimeError):
    """Raised when the real AIOpsLab package cannot be imported from the given path."""


def _stub_orchestrator_package(repo_path: str) -> None:
    """Register `aiopslab.orchestrator` in sys.modules without executing its
    real __init__.py (which is what pulls in the problems/tasks/evaluators
    cascade). Its __path__ must still point at the real on-disk directory
    so that importing real submodules (`.actions.base`, `.parser`) resolves
    normally -- only the package's own __init__.py body is skipped.
    """
    name = "aiopslab.orchestrator"
    if name in sys.modules:
        return
    stub = types.ModuleType(name)
    stub.__path__ = [str(Path(repo_path) / "aiopslab" / "orchestrator")]
    sys.modules[name] = stub


def import_real_aiopslab(repo_path: str | Path):
    """Import the real TaskActions/ResponseParser/Shell classes from a
    cloned microsoft/AIOpsLab checkout at `repo_path`.

    Requires `<repo_path>/aiopslab/config.yml` to exist (copy it from
    `config.yml.example`; `k8s_host: localhost` is enough to import --
    no cluster is contacted at import time) and a structurally valid
    kubeconfig at the path its `monitor_config.yaml` names (a dummy
    file with cluster/context/user stanzas is enough; nothing here
    connects to it, `kubernetes.config.load_kube_config` only parses
    the YAML shape at import time).

    Returns a namespace with the real classes/modules bound. Idempotent:
    safe to call more than once (subsequent calls reuse `sys.modules`).
    """
    repo_path = str(Path(repo_path).resolve())
    if not (Path(repo_path) / "aiopslab").is_dir():
        raise AIOpsLabNotFoundError(f"no 'aiopslab' package found under {repo_path}")

    if repo_path not in sys.path:
        sys.path.insert(0, repo_path)

    _stub_orchestrator_package(repo_path)

    try:
        base = importlib.import_module("aiopslab.orchestrator.actions.base")
        parser_mod = importlib.import_module("aiopslab.orchestrator.parser")
        shell_mod = importlib.import_module("aiopslab.service.shell")
    except ImportError as exc:
        raise AIOpsLabNotFoundError(
            f"could not import the real AIOpsLab package from {repo_path}: {exc}"
        ) from exc

    return types.SimpleNamespace(
        repo_path=repo_path,
        base_module=base,
        parser_module=parser_mod,
        TaskActions=base.TaskActions,
        ResponseParser=parser_mod.ResponseParser,
        Shell=shell_mod.Shell,
    )
