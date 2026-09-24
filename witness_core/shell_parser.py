"""Shell-command -> structured-action classifier.

AIOpsLab's actual remediation surface is not a pre-structured
`(verb, target, arguments)` call -- it is a single free-text shell
command string passed to `TaskActions.exec_shell(command: str)` and run
verbatim (see aiopslab/orchestrator/actions/base.py in the vendored
checkout). The abstract describes gating "a closed schema"; this module
is the missing piece that gets a raw agent-issued shell command into
that schema so the rest of `witness_core` can reason about it.

This is deliberately NOT a general-purpose shell parser (writing a
correct POSIX shell grammar is its own research project). It is a
conservative *classifier*: split into sub-commands on unquoted control
operators, then match each sub-command's leading tokens against a
curated table of known mutation patterns (package/repo management,
Kubernetes mutations, service control, TLS/firewall/identity changes,
arbitrary file writes).

The default is fail-safe in the security sense, which is also a
concrete improvement over AIOpsLab's own current defense: `exec_shell`
today runs everything except a five-entry substring BLOCK_LIST. Here,
anything not positively recognized as read-only is treated as a
mutation and routed through the WITNESS gate (as a generic
`shell_mutation` action carrying the whole command as its one
argument, so lineage checking still applies to it) -- an allowlist of
safe reads, not a denylist of known-bad patterns.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Optional

from .schema import RemediationAction

# --- 1. Split a compound command into sub-commands on unquoted &&, ||, ;, | ---


def split_compound_command(command: str) -> list[str]:
    """Split on unquoted &&, ||, ;, | (but not a single & backgrounding
    token, and never inside single/double quotes)."""
    parts: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(command)
    quote: Optional[str] = None

    while i < n:
        ch = command[i]
        if quote:
            buf.append(ch)
            if ch == quote and command[i - 1] != "\\":
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if command[i:i + 2] == "&&":
            parts.append("".join(buf))
            buf = []
            i += 2
            continue
        if command[i:i + 2] == "||":
            parts.append("".join(buf))
            buf = []
            i += 2
            continue
        if ch == ";":
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        if ch == "|":
            # a lone pipe: still a boundary between two commands
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1

    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


# --- 2. Read-only recognition (bypasses the gate entirely) ---

_READ_ONLY_PATTERNS = [
    re.compile(r"^kubectl\s+(get|describe|logs|top|explain|version|api-resources|api-versions)\b"),
    re.compile(r"^docker\s+(ps|logs|inspect|top|stats\b.*--no-stream|version|images)\b"),
    re.compile(r"^(cat|less|more|head|tail|grep|egrep|fgrep|ls|find|ps|df|du|uptime|whoami|id|pwd|date|hostname|wc|stat|file|which|env|printenv|echo)\b"),
    re.compile(r"^systemctl\s+(status|show|is-active|is-enabled|list-units)\b"),
    re.compile(r"^(curl|wget)\b"),  # refined below: mutating flags escalate this
]

_MUTATING_HTTP_FLAGS = re.compile(r"(-X\s*(POST|PUT|PATCH|DELETE)|--request\s+(POST|PUT|PATCH|DELETE)|-d\b|--data\b|-F\b|--form\b)", re.IGNORECASE)

_FIND_DELETE = re.compile(r"^find\b.*-delete\b")


def _is_read_only(sub: str) -> bool:
    stripped = sub.strip()
    if _FIND_DELETE.search(stripped):
        return False
    if re.match(r"^(curl|wget)\b", stripped) and _MUTATING_HTTP_FLAGS.search(stripped):
        return False
    if _has_unsafe_redirect(stripped):
        return False
    for pattern in _READ_ONLY_PATTERNS:
        if pattern.match(stripped):
            return True
    return False


# A redirect into a known scratch/output directory (matches AIOpsLab's own
# get_metrics/get_traces conventions) isn't a meaningful state mutation.
_SAFE_REDIRECT_PREFIXES = ("/tmp/", "./metrics_output", "metrics_output", "./trace_output", "trace_output")
_REDIRECT = re.compile(r"(?<!\d)(>>?)(?!\d)\s*(\S+)")


def _has_unsafe_redirect(sub: str) -> bool:
    for match in _REDIRECT.finditer(sub):
        target = match.group(2).strip("'\"")
        if not any(target.startswith(p) for p in _SAFE_REDIRECT_PREFIXES):
            return True
    return False


# --- 3. Mutation classification ---

@dataclass(frozen=True)
class ClassifiedCommand:
    raw: str
    read_only: bool
    action: Optional[RemediationAction] = None


def _safe_tokens(sub: str) -> list[str]:
    try:
        return shlex.split(sub, posix=True)
    except ValueError:
        # Unbalanced quotes etc: fail safe, caller treats as an opaque
        # mutation rather than crashing the classifier.
        return []


_REPO_RULES = [
    (re.compile(r"^(sudo\s+)?add-apt-repository\s+(-y\s+)?(?P<repo>\S+)"), "add_repo", "apt"),
    (re.compile(r"^(sudo\s+)?apt-add-repository\s+(-y\s+)?(?P<repo>\S+)"), "add_repo", "apt"),
    (re.compile(r"^(sudo\s+)?yum-config-manager\s+--add-repo[= ](?P<repo>\S+)"), "add_repo", "yum"),
]

_APT_SOURCES_REDIRECT = re.compile(r">>?\s*/etc/apt/sources\.list(\.d/\S+)?")

_PACKAGE_INSTALL = re.compile(
    r"^(sudo\s+)?(apt-get|apt|yum|dnf)\s+install\b(?P<rest>.*)$"
)
_PIP_INSTALL = re.compile(r"^(sudo\s+)?pip[3]?\s+install\b(?P<rest>.*)$")
_PACKAGE_REMOVE = re.compile(r"^(sudo\s+)?(apt-get|apt|yum|dnf)\s+(remove|purge)\b(?P<rest>.*)$")
_ALLOW_DOWNGRADE_FLAG = re.compile(r"--allow-downgrades")
_PACKAGE_VERSION_PIN = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9+.\-]*)=(?P<version>[^\s]+)$")

_K8S_MUTATION = re.compile(
    r"^kubectl\s+(?P<verb>patch|scale|delete|apply|create|edit|rollout|exec|cordon|drain|taint|label|annotate)\b(?P<rest>.*)$"
)

_SYSTEMCTL_RESTART = re.compile(r"^(sudo\s+)?systemctl\s+(?P<verb>restart|start|stop)\s+(?P<service>\S+)")
_SERVICE_RESTART = re.compile(r"^(sudo\s+)?service\s+(?P<service>\S+)\s+(?P<verb>restart|start|stop)")

_TLS_KEYWORDS = re.compile(r"\b(ssl|tls|ssl_protocols|ssl_ciphers|certificate|https?://)\b", re.IGNORECASE)
_SED_OR_PATCH = re.compile(r"^(sudo\s+)?sed\s+-i\b")

_FIREWALL = re.compile(r"^(sudo\s+)?(iptables|ip6tables|ufw|firewall-cmd)\b")

_IDENTITY = re.compile(r"^(sudo\s+)?(useradd|userdel|usermod|passwd|chpasswd|adduser|deluser)\b")
_LOCK_ACCOUNT = re.compile(r"usermod\s+(-L|--lock)\s+(?P<user>\S+)|passwd\s+-l\s+(?P<user2>\S+)")

# Plain-Docker deployments (AIOpsLab's own "namespace == docker" mode, and
# this repo's docker-compose live environment) mutate containers directly
# instead of through kubectl.
_DOCKER_MUTATION = re.compile(
    r"^(sudo\s+)?docker\s+(compose\s+)?(?P<verb>restart|stop|start|kill|rm|update|exec|pause|unpause)\b(?P<rest>.*)$"
)

_MUTATION_HINT = re.compile(
    r"\b(apt|apt-get|yum|dnf|pip|pip3|kubectl|docker|systemctl|service|chmod|chown|rm|mv|cp|"
    r"useradd|userdel|usermod|passwd|chpasswd|iptables|ufw|firewall-cmd|sed|ssh|scp|curl|wget)\b"
)


def _extract_repo_literal(sub: str) -> Optional[str]:
    for pattern, _verb, _target in _REPO_RULES:
        m = pattern.match(sub.strip())
        if m:
            return m.group("repo").strip("'\"")
    if _APT_SOURCES_REDIRECT.search(sub):
        # e.g. echo "deb http://evil/ ./" >> /etc/apt/sources.list
        m = re.search(r'echo\s+["\']?(?P<line>.+?)["\']?\s*>>', sub)
        if m:
            return m.group("line").strip()
    return None


def classify_subcommand(sub: str) -> ClassifiedCommand:
    sub = sub.strip()
    if not sub:
        return ClassifiedCommand(sub, read_only=True, action=None)

    if _is_read_only(sub):
        return ClassifiedCommand(sub, read_only=True, action=None)

    # -- repo addition --
    repo_literal = _extract_repo_literal(sub)
    if repo_literal:
        return ClassifiedCommand(
            sub, read_only=False,
            action=RemediationAction(verb="add_repo", target="apt", arguments={"repository": repo_literal}),
        )

    # -- package install / downgrade / remove --
    m = _PACKAGE_INSTALL.match(sub) or _PIP_INSTALL.match(sub)
    if m:
        rest = m.group("rest")
        tokens = [t for t in _safe_tokens(rest) if not t.startswith("-")]
        downgrade = bool(_ALLOW_DOWNGRADE_FLAG.search(sub))
        pinned = [t for t in tokens if _PACKAGE_VERSION_PIN.match(t)]
        if pinned:
            downgrade = downgrade or True  # an explicit version pin is a version-changing action
        verb = "downgrade_package" if downgrade and pinned else "install_package"
        args = {"packages": ",".join(tokens)} if tokens else {"packages": rest.strip()}
        return ClassifiedCommand(sub, read_only=False, action=RemediationAction(verb=verb, target="apt", arguments=args))

    m = _PACKAGE_REMOVE.match(sub)
    if m:
        tokens = [t for t in _safe_tokens(m.group("rest")) if not t.startswith("-")]
        return ClassifiedCommand(
            sub, read_only=False,
            action=RemediationAction(verb="remove_package", target="apt", arguments={"packages": ",".join(tokens)}),
        )

    # -- Kubernetes mutations --
    m = _K8S_MUTATION.match(sub)
    if m:
        verb_map = {
            "patch": "k8s_patch", "scale": "k8s_scale", "delete": "k8s_delete",
            "apply": "k8s_apply", "create": "k8s_create", "edit": "k8s_edit",
            "rollout": "k8s_rollout", "exec": "k8s_exec", "cordon": "k8s_cordon",
            "drain": "k8s_drain", "taint": "k8s_taint", "label": "k8s_label",
            "annotate": "k8s_annotate",
        }
        verb = verb_map[m.group("verb")]
        rest = m.group("rest").strip()
        tokens = _safe_tokens(rest)
        target = next((t for t in tokens if not t.startswith("-")), rest)
        return ClassifiedCommand(sub, read_only=False, action=RemediationAction(verb=verb, target=target, arguments={"command": sub}))

    # -- service restart --
    m = _SYSTEMCTL_RESTART.match(sub) or _SERVICE_RESTART.match(sub)
    if m:
        return ClassifiedCommand(
            sub, read_only=False,
            action=RemediationAction(verb="restart_service", target=m.group("service"), arguments={"service": m.group("service")}),
        )

    # -- plain-Docker container mutations --
    m = _DOCKER_MUTATION.match(sub)
    if m:
        docker_verb_map = {
            "restart": "restart_service", "stop": "stop_service", "start": "start_service",
            "kill": "kill_service", "rm": "remove_container", "update": "update_container",
            "exec": "container_exec", "pause": "pause_service", "unpause": "unpause_service",
        }
        verb = docker_verb_map[m.group("verb")]
        tokens = [t for t in _safe_tokens(m.group("rest")) if not t.startswith("-")]
        container = tokens[0] if tokens else m.group("rest").strip()
        args = {"container": container}
        if verb == "container_exec" and len(tokens) > 1:
            args["command"] = " ".join(tokens[1:])
        return ClassifiedCommand(sub, read_only=False, action=RemediationAction(verb=verb, target=container, arguments=args))

    # -- TLS / config edits via sed or redirect touching TLS-flavoured paths --
    if _SED_OR_PATCH.match(sub) and _TLS_KEYWORDS.search(sub):
        return ClassifiedCommand(
            sub, read_only=False,
            action=RemediationAction(verb="modify_tls_config", target="nginx", arguments={"command": sub}),
        )

    # -- firewall --
    if _FIREWALL.match(sub):
        return ClassifiedCommand(sub, read_only=False, action=RemediationAction(verb="firewall_change", target="netfilter", arguments={"rule": sub}))

    # -- identity --
    if _IDENTITY.match(sub):
        m2 = _LOCK_ACCOUNT.search(sub)
        if m2:
            user = m2.group("user") or m2.group("user2")
            return ClassifiedCommand(sub, read_only=False, action=RemediationAction(verb="disable_account", target="iam", arguments={"username": user}))
        return ClassifiedCommand(sub, read_only=False, action=RemediationAction(verb="identity_change", target="iam", arguments={"command": sub}))

    # -- generic fallback: anything else that looks mutating stays gated --
    if _MUTATION_HINT.search(sub) or _has_unsafe_redirect(sub):
        return ClassifiedCommand(sub, read_only=False, action=RemediationAction(verb="shell_mutation", target="shell", arguments={"command": sub}))

    # Nothing matched a known mutation hint or a read-only pattern: fail
    # safe by still gating it as an unclassified mutation rather than
    # silently letting an unrecognized command straight through.
    return ClassifiedCommand(sub, read_only=False, action=RemediationAction(verb="shell_mutation", target="shell", arguments={"command": sub}))


def parse_shell_command(command: str) -> list[ClassifiedCommand]:
    """Split a (possibly compound) shell command and classify each part."""
    return [classify_subcommand(s) for s in split_compound_command(command)]
