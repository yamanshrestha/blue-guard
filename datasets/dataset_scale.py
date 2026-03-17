from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

HOST = "server"

NORMAL_USERS = ["alice", "bob", "charlie", "yaman", "dev", "ops", "ubuntu", "analyst"]
ATTACK_USERS = [
    "root", "admin", "test", "guest", "ubuntu", "oracle", "postgres",
    "ftp", "mysql", "backup", "deploy", "devops", "ansible", "jenkins"
]

NORMAL_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30",
    "10.0.0.5", "10.0.0.10", "10.1.2.15",
    "172.16.1.15", "172.16.1.25"
]

ATTACK_IPS = [
    "185.234.217.12", "45.67.89.10", "103.45.67.89",
    "198.51.100.23", "203.0.113.77", "91.240.118.14"
]

COMMANDS = [
    "/usr/bin/id",
    "/bin/cat /etc/shadow",
    "/usr/bin/whoami",
    "/bin/ls /root",
    "/usr/bin/journalctl -xe",
    "/usr/bin/systemctl restart ssh"
]


def ts_str(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S")


def random_pid() -> int:
    return random.randint(10000, 99999)


def random_port() -> int:
    return random.randint(20000, 65000)


def ssh_failed(dt: datetime, ip: str, username: str) -> str:
    return (
        f"{ts_str(dt)} {HOST} sshd[{random_pid()}]: "
        f"Failed password for {username} from {ip} port {random_port()} ssh2"
    )


def ssh_failed_invalid_user(dt: datetime, ip: str, username: str) -> str:
    return (
        f"{ts_str(dt)} {HOST} sshd[{random_pid()}]: "
        f"Failed password for invalid user {username} from {ip} port {random_port()} ssh2"
    )


def ssh_accepted_password(dt: datetime, ip: str, username: str) -> str:
    return (
        f"{ts_str(dt)} {HOST} sshd[{random_pid()}]: "
        f"Accepted password for {username} from {ip} port {random_port()} ssh2"
    )


def ssh_accepted_publickey(dt: datetime, ip: str, username: str) -> str:
    return (
        f"{ts_str(dt)} {HOST} sshd[{random_pid()}]: "
        f"Accepted publickey for {username} from {ip} port {random_port()} ssh2"
    )


def sudo_command(dt: datetime, username: str, tty: str) -> str:
    return (
        f"{ts_str(dt)} {HOST} sudo:    {username} : "
        f"TTY={tty} ; PWD=/home/{username} ; USER=root ; COMMAND={random.choice(COMMANDS)}"
    )


def sudo_auth_failure(dt: datetime, username: str, tty: str) -> str:
    return (
        f"{ts_str(dt)} {HOST} sudo: pam_unix(sudo:auth): authentication failure; "
        f"logname={username} uid=1000 euid=0 tty=/dev/{tty} ruser={username} rhost=  user={username}"
    )


def generate_normal_event(current: datetime) -> str:
    ip = random.choice(NORMAL_IPS)
    user = random.choice(NORMAL_USERS)
    roll = random.random()

    if roll < 0.68:
        return ssh_accepted_password(current, ip, user)
    elif roll < 0.88:
        return ssh_accepted_publickey(current, ip, user)
    elif roll < 0.96:
        return ssh_failed(current, ip, user)
    else:
        return ssh_failed_invalid_user(current, ip, random.choice(ATTACK_USERS))


def brute_force_campaign(start: datetime, ip: str, attempts: int = 8) -> list[str]:
    lines = []
    users = ["root", "admin", "root", "ubuntu", "root", "test", "root", "guest", "admin", "root"]
    current = start
    for i in range(attempts):
        current += timedelta(seconds=random.randint(3, 8))
        lines.append(ssh_failed(current, ip, users[i % len(users)]))
    return lines


def credential_stuffing_campaign(start: datetime, ip: str, usernames: int = 12) -> list[str]:
    lines = []
    current = start
    chosen = ATTACK_USERS[:]
    random.shuffle(chosen)
    selected = chosen[:usernames]

    for username in selected:
        current += timedelta(seconds=random.randint(2, 5))
        if random.random() < 0.35:
            lines.append(ssh_failed_invalid_user(current, ip, username))
        else:
            lines.append(ssh_failed(current, ip, username))
    return lines


def privilege_escalation_campaign(start: datetime, username: str, tty_num: int) -> list[str]:
    tty = f"pts/{tty_num}"
    return [
        sudo_command(start + timedelta(seconds=3), username, tty),
        sudo_auth_failure(start + timedelta(seconds=7), username, tty),
    ]


def off_hours_login_event(start: datetime, username: str, ip: str) -> str:
    if random.random() < 0.5:
        return ssh_accepted_password(start, ip, username)
    return ssh_accepted_publickey(start, ip, username)


def build_large_log(target_lines: int = 100_000, seed: int = 42) -> int:
    random.seed(seed)
    out_dir = Path("sample_logs")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "auth_100k.log"

    current = datetime(2024, 3, 14, 0, 0, 0)
    written = 0

    with out_file.open("w", encoding="utf-8") as f:
        while written < target_lines:
            # Inject attacks occasionally
            attack_roll = random.random()

            if attack_roll < 0.02 and written + 10 <= target_lines:
                # Brute force
                start = current
                ip = random.choice(ATTACK_IPS)
                campaign = brute_force_campaign(start, ip, attempts=random.randint(6, 10))
                for line in campaign:
                    f.write(line + "\n")
                written += len(campaign)
                current += timedelta(minutes=random.randint(3, 10))
                continue

            if 0.02 <= attack_roll < 0.035 and written + 12 <= target_lines:
                # Credential stuffing
                start = current
                ip = random.choice(ATTACK_IPS)
                campaign = credential_stuffing_campaign(start, ip, usernames=random.randint(10, 14))
                for line in campaign:
                    f.write(line + "\n")
                written += len(campaign)
                current += timedelta(minutes=random.randint(5, 15))
                continue

            if 0.035 <= attack_roll < 0.04 and written + 2 <= target_lines:
                # Privilege escalation sequence
                start = current
                user = random.choice(["yaman", "dev", "ops", "alice"])
                campaign = privilege_escalation_campaign(start, user, tty_num=random.randint(0, 5))
                for line in campaign:
                    f.write(line + "\n")
                written += len(campaign)
                current += timedelta(minutes=random.randint(10, 20))
                continue

            if 0.04 <= attack_roll < 0.045 and written + 1 <= target_lines:
                # Off-hours login
                # force time into off-hours by setting hour manually sometimes
                off_hour = random.choice([1, 2, 3, 4, 5, 6, 22, 23])
                current = current.replace(hour=off_hour, minute=random.randint(0, 59), second=random.randint(0, 59))
                line = off_hours_login_event(
                    current,
                    username=random.choice(NORMAL_USERS),
                    ip=random.choice(["203.0.113.10", "198.51.100.77", "198.51.100.88"])
                )
                f.write(line + "\n")
                written += 1
                current += timedelta(minutes=random.randint(5, 25))
                continue

            # Normal background event
            business_hour = random.randint(8, 18)
            current = current.replace(hour=business_hour, minute=random.randint(0, 59), second=random.randint(0, 59))
            line = generate_normal_event(current)
            f.write(line + "\n")
            written += 1
            current += timedelta(seconds=random.randint(5, 90))

    print(f"Wrote {written} lines to {out_file}")
    return written


if __name__ == "__main__":
    build_large_log(target_lines=100_000) #for more change the target_lines parameter like 500_000 or 1_000_000