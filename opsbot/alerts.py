"""
Alert Manager — multi-channel alert delivery.

Supports Slack, Discord, Telegram, and PagerDuty.
Rich formatting with severity colors and structured messages.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib import request, error

from opsbot.config import AlertConfig

logger = logging.getLogger(__name__)


@dataclass
class Alert:
    """An alert to be sent."""
    title: str
    message: str
    severity: str  # low, medium, high, critical
    source: str = "opsbot"
    timestamp: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    channels: List[str] = field(default_factory=list)  # empty = all channels

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class AlertDelivery:
    """Record of an alert delivery attempt."""
    alert_title: str
    channel: str
    success: bool
    timestamp: str
    error: Optional[str] = None


# Severity color maps for rich messages
_SEVERITY_COLORS = {
    "low": "#36a64f",       # green
    "medium": "#ff9900",    # orange
    "high": "#ff3300",      # red-orange
    "critical": "#cc0000",  # dark red
}

_SEVERITY_EMOJI = {
    "low": "ℹ️",
    "medium": "⚠️",
    "high": "🔴",
    "critical": "🚨",
}


class AlertManager:
    """Manages alert delivery across multiple channels."""

    def __init__(self, config: Optional[AlertConfig] = None):
        self.config = config or AlertConfig()
        self._delivery_log: List[AlertDelivery] = []
        self._custom_channels: Dict[str, callable] = {}

    def register_channel(self, name: str, sender: callable):
        """Register a custom alert channel."""
        self._custom_channels[name] = sender

    def send(self, alert: Alert) -> List[AlertDelivery]:
        """Send an alert to configured channels."""
        deliveries = []
        channels = alert.channels if alert.channels else self._get_active_channels()

        for channel in channels:
            try:
                success = self._send_to_channel(channel, alert)
                delivery = AlertDelivery(
                    alert_title=alert.title,
                    channel=channel,
                    success=success,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
            except Exception as e:
                delivery = AlertDelivery(
                    alert_title=alert.title,
                    channel=channel,
                    success=False,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    error=str(e),
                )
                logger.error("Failed to send alert to %s: %s", channel, e)

            deliveries.append(delivery)
            self._delivery_log.append(delivery)

        return deliveries

    def _get_active_channels(self) -> List[str]:
        """Return list of configured (active) channels."""
        channels = []
        if self.config.slack_webhook:
            channels.append("slack")
        if self.config.discord_webhook:
            channels.append("discord")
        if self.config.telegram_bot_token and self.config.telegram_chat_id:
            channels.append("telegram")
        if self.config.pagerduty_token:
            channels.append("pagerduty")
        channels.extend(self._custom_channels.keys())
        return channels

    def _send_to_channel(self, channel: str, alert: Alert) -> bool:
        """Route alert to the appropriate channel sender."""
        if channel == "slack":
            return self._send_slack(alert)
        elif channel == "discord":
            return self._send_discord(alert)
        elif channel == "telegram":
            return self._send_telegram(alert)
        elif channel == "pagerduty":
            return self._send_pagerduty(alert)
        elif channel in self._custom_channels:
            return self._custom_channels[channel](alert)
        else:
            logger.warning("Unknown channel: %s", channel)
            return False

    def _send_slack(self, alert: Alert) -> bool:
        """Send alert to Slack via webhook."""
        if not self.config.slack_webhook:
            return False

        color = _SEVERITY_COLORS.get(alert.severity, "#999999")
        emoji = _SEVERITY_EMOJI.get(alert.severity, "❓")

        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": f"{emoji} {alert.title}",
                    "text": alert.message,
                    "fields": [
                        {"title": "Severity", "value": alert.severity.upper(), "short": True},
                        {"title": "Source", "value": alert.source, "short": True},
                        {"title": "Time", "value": alert.timestamp, "short": False},
                    ],
                    "footer": "OpsBot",
                    "ts": int(datetime.now(timezone.utc).timestamp()),
                }
            ]
        }

        if alert.metadata:
            for k, v in list(alert.metadata.items())[:5]:
                payload["attachments"][0]["fields"].append({
                    "title": k, "value": str(v)[:100], "short": True
                })

        return self._post_json(self.config.slack_webhook, payload)

    def _send_discord(self, alert: Alert) -> bool:
        """Send alert to Discord via webhook."""
        if not self.config.discord_webhook:
            return False

        color = int(_SEVERITY_COLORS.get(alert.severity, "#999999").lstrip("#"), 16)
        emoji = _SEVERITY_EMOJI.get(alert.severity, "❓")

        payload = {
            "embeds": [
                {
                    "title": f"{emoji} {alert.title}",
                    "description": alert.message,
                    "color": color,
                    "fields": [
                        {"name": "Severity", "value": alert.severity.upper(), "inline": True},
                        {"name": "Source", "value": alert.source, "inline": True},
                    ],
                    "footer": {"text": "OpsBot"},
                    "timestamp": alert.timestamp,
                }
            ]
        }

        return self._post_json(self.config.discord_webhook, payload)

    def _send_telegram(self, alert: Alert) -> bool:
        """Send alert to Telegram via Bot API."""
        if not self.config.telegram_bot_token or not self.config.telegram_chat_id:
            return False

        emoji = _SEVERITY_EMOJI.get(alert.severity, "❓")
        text = (
            f"{emoji} *{alert.title}*\n\n"
            f"{alert.message}\n\n"
            f"*Severity:* {alert.severity.upper()}\n"
            f"*Source:* {alert.source}\n"
            f"*Time:* {alert.timestamp}"
        )

        url = f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage"
        payload = {
            "chat_id": self.config.telegram_chat_id,
            "text": text,
            "parse_mode": "Markdown",
        }

        return self._post_json(url, payload)

    def _send_pagerduty(self, alert: Alert) -> bool:
        """Send alert to PagerDuty via Events API v2."""
        if not self.config.pagerduty_token:
            return False

        severity_map = {
            "low": "info",
            "medium": "warning",
            "high": "error",
            "critical": "critical",
        }

        payload = {
            "routing_key": self.config.pagerduty_token,
            "event_action": "trigger",
            "payload": {
                "summary": f"{alert.title}: {alert.message[:200]}",
                "severity": severity_map.get(alert.severity, "warning"),
                "source": alert.source,
                "component": "opsbot",
                "custom_details": alert.metadata,
            },
        }

        if self.config.pagerduty_service_id:
            payload["payload"]["group"] = self.config.pagerduty_service_id

        return self._post_json("https://events.pagerduty.com/v2/enqueue", payload)

    def _post_json(self, url: str, payload: dict) -> bool:
        """POST JSON payload to a URL."""
        try:
            data = json.dumps(payload).encode("utf-8")
            req = request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with request.urlopen(req, timeout=10) as resp:
                return resp.status in (200, 201, 202, 204)
        except error.HTTPError as e:
            logger.error("HTTP %d from %s: %s", e.code, url, e.read().decode()[:200])
            return False
        except Exception as e:
            logger.error("Request to %s failed: %s", url, e)
            return False

    def send_simple(self, title: str, message: str, severity: str = "medium") -> List[AlertDelivery]:
        """Convenience method to send a simple alert."""
        alert = Alert(title=title, message=message, severity=severity)
        return self.send(alert)

    def get_delivery_log(self) -> List[AlertDelivery]:
        """Return the delivery log."""
        return list(self._delivery_log)
