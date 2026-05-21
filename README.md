# 🤖 OpsBot — AI-Powered DevOps Automation

At 3am my server ran out of disk. By the time I woke up, OpsBot had already cleaned up the logs, killed the runaway process, and sent me a Slack with a full incident report.

OpsBot monitors your servers, analyzes logs, diagnoses root causes, and auto-remediates issues — all driven by YAML playbooks you can customize.

## Features

- **System Monitoring** — CPU, memory, disk, load average, Docker containers
- **Log Analysis** — Pattern matching, error clustering, anomaly detection
- **Diagnostic Engine** — Correlates metrics + logs to find root causes
- **Auto-Remediation** — 16 built-in handlers (disk cleanup, service restart, cache drop, etc.)
- **YAML Playbooks** — Define custom remediation workflows
- **Multi-Channel Alerts** — Slack, Discord, Telegram, PagerDuty
- **Streamlit Dashboard** — Real-time gauges and system overview

## Quick Start

```bash
# Install
pip install -e .

# Run once
python -m opsbot.app --once

# Run continuously
python -m opsbot.app --interval 30

# With dry-run (no actual remediation)
python -m opsbot.app --dry-run

# Dashboard
streamlit run opsbot/dashboard.py
```

## Configuration

### Environment Variables

```bash
export OPSBOT_SLACK_WEBHOOK="https://hooks.slack.com/..."
export OPSBOT_DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
export OPSBOT_TELEGRAM_BOT_TOKEN="123456:ABC..."
export OPSBOT_TELEGRAM_CHAT_ID="-1001234567890"
export OPSBOT_CPU_THRESHOLD=90
export OPSBOT_MEMORY_THRESHOLD=85
export OPSBOT_DISK_THRESHOLD=90
```

### Config File (opsbot.yaml)

```yaml
monitor:
  cpu_threshold: 90
  memory_threshold: 85
  disk_threshold: 90
  check_interval: 30
  docker_enabled: true

alerts:
  slack_webhook: "https://hooks.slack.com/..."
  discord_webhook: "https://discord.com/api/webhooks/..."

logs:
  log_paths:
    - /var/log/syslog
    - /var/log/auth.log
  tail_lines: 1000

remediation:
  enabled: true
  dry_run: false
  max_actions_per_hour: 10
  playbook_dir: playbooks
```

## Playbooks

OpsBot uses YAML playbooks for custom remediation workflows. See the `playbooks/` directory for examples.

```yaml
name: disk_cleanup
description: "Automated disk cleanup"
steps:
  - name: check_disk
    action: check
    condition: "disk_percent > 85"
  - name: clean_logs
    action: command
    command: "find /var/log -name '*.log' -mtime +7 -delete"
  - name: alert
    action: alert
    command: "Disk cleanup completed"
```

## Built-in Remediation Handlers

| Handler | Description |
|---------|-------------|
| clean_old_logs | Delete log files older than 7 days |
| clean_tmp_files | Clean /tmp files older than 3 days |
| clean_docker_images | Prune unused Docker images |
| clean_docker_volumes | Prune unused Docker volumes |
| clean_journal_logs | Vacuum journald to 500MB |
| compress_old_logs | Compress uncompressed log files |
| restart_docker_container | Restart exited/dead containers |
| restart_failed_service | Restart failed systemd services |
| kill_zombie_processes | Kill zombie processes |
| kill_memory_hogs | SIGTERM to top memory consumer |
| drop_caches | Drop kernel page caches |
| resize_swap | Create/activate 2GB swap file |
| limit_cpu_cgroup | Limit CPU for runaway processes |
| block_offending_ip | Block IPs via iptables |
| rotate_logs | Force log rotation |
| notify_only | Alert without action |

## Docker

```bash
docker-compose up -d
```

## License

MIT
