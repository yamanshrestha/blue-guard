from collections import defaultdict, deque
from datetime import timedelta


class DetectionEngine:
    def __init__(
        self,
        brute_force_threshold=5,
        brute_force_window_seconds=60,
        credential_stuffing_user_threshold=10,
        credential_stuffing_window_seconds=300,
        sudo_window_seconds=120,
        business_hours_start=8,
        business_hours_end=18,
    ):
        self.brute_force_threshold = brute_force_threshold
        self.brute_force_window = timedelta(seconds=brute_force_window_seconds)

        self.credential_stuffing_user_threshold = credential_stuffing_user_threshold
        self.credential_stuffing_window = timedelta(seconds=credential_stuffing_window_seconds)

        self.sudo_window = timedelta(seconds=sudo_window_seconds)

        self.business_hours_start = business_hours_start
        self.business_hours_end = business_hours_end

        # Rolling state
        self.failed_by_ip = defaultdict(deque)              # ip -> deque[timestamp]
        self.failed_users_by_ip = defaultdict(deque)        # ip -> deque[(timestamp, username)]
        self.sudo_commands_by_user = defaultdict(deque)     # user -> deque[timestamp]

    def _prune_old(self, dq, current_time, window):
        while dq and current_time - dq[0][0] > window if isinstance(dq[0], tuple) else current_time - dq[0] > window:
            dq.popleft()

    def process_event(self, event):
        """
        Process one normalized event dictionary.
        Returns a list of alert dictionaries triggered by this event.
        """
        if not event:
            return []

        event_type = event["event_type"]
        alerts = []

        if event_type == "failed_login":
            alerts.extend(self._check_brute_force(event))
            alerts.extend(self._check_credential_stuffing(event))

        elif event_type == "accepted_login":
            alert = self._check_off_hours_login(event)
            if alert:
                alerts.append(alert)

        elif event_type == "sudo_command":
            self._track_sudo_command(event)

        elif event_type == "sudo_auth_failure":
            alert = self._check_privilege_escalation(event)
            if alert:
                alerts.append(alert)

        return alerts

    def _check_brute_force(self, event):
        ts = event["timestamp"]
        ip = event["source_ip"]
        username = event["username"]

        dq = self.failed_by_ip[ip]
        dq.append(ts)

        while dq and ts - dq[0] > self.brute_force_window:
            dq.popleft()

        if len(dq) >= self.brute_force_threshold:
            return [{
                "timestamp": ts.isoformat(),
                "rule": "brute_force",
                "mitre_technique": "T1110",
                "severity": "HIGH",
                "source_ip": ip,
                "username": username,
                "count": len(dq),
                "window_seconds": int(self.brute_force_window.total_seconds()),
                "description": f"{len(dq)} failed login attempts from {ip} in {int(self.brute_force_window.total_seconds())}s"
            }]

        return []

    def _check_credential_stuffing(self, event):
        ts = event["timestamp"]
        ip = event["source_ip"]
        username = event["username"]

        dq = self.failed_users_by_ip[ip]
        dq.append((ts, username))

        while dq and ts - dq[0][0] > self.credential_stuffing_window:
            dq.popleft()

        unique_users = {user for _, user in dq}

        if len(unique_users) >= self.credential_stuffing_user_threshold:
            return [{
                "timestamp": ts.isoformat(),
                "rule": "credential_stuffing",
                "mitre_technique": "T1078",
                "severity": "HIGH",
                "source_ip": ip,
                "username": None,
                "count": len(unique_users),
                "window_seconds": int(self.credential_stuffing_window.total_seconds()),
                "description": f"{ip} attempted logins across {len(unique_users)} distinct usernames in {int(self.credential_stuffing_window.total_seconds())}s"
            }]

        return []

    def _track_sudo_command(self, event):
        ts = event["timestamp"]
        username = event["username"]

        dq = self.sudo_commands_by_user[username]
        dq.append(ts)

        while dq and ts - dq[0] > self.sudo_window:
            dq.popleft()

    def _check_privilege_escalation(self, event):
        ts = event["timestamp"]
        username = event["username"]

        dq = self.sudo_commands_by_user[username]

        while dq and ts - dq[0] > self.sudo_window:
            dq.popleft()

        if dq:
            return {
                "timestamp": ts.isoformat(),
                "rule": "privilege_escalation",
                "mitre_technique": "T1548",
                "severity": "MEDIUM",
                "source_ip": None,
                "username": username,
                "count": len(dq),
                "window_seconds": int(self.sudo_window.total_seconds()),
                "description": f"Sudo authentication failure observed for {username} shortly after sudo command execution"
            }

        return None

    def _check_off_hours_login(self, event):
        ts = event["timestamp"]
        ip = event["source_ip"]
        username = event["username"]

        if ts.hour < self.business_hours_start or ts.hour >= self.business_hours_end:
            return {
                "timestamp": ts.isoformat(),
                "rule": "off_hours_login",
                "mitre_technique": "N/A",
                "severity": "LOW",
                "source_ip": ip,
                "username": username,
                "count": 1,
                "window_seconds": 0,
                "description": f"Successful login for {username} from {ip} outside business hours"
            }

        return None