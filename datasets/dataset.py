# import random
# from datetime import datetime, timedelta

# users = ["root","admin","test","ubuntu","user","guest","alice","bob","charlie"]
# ips = ["185.234.217.12","45.67.89.10","103.45.67.89","192.168.1.50","10.0.0.5"]

# start = datetime(2024,3,14,0,0,0)

# lines = []

# for i in range(500):
#     ts = start + timedelta(seconds=i*2)
#     ts_str = ts.strftime("%b %d %H:%M:%S")

#     ip = random.choice(ips)
#     user = random.choice(users)
#     pid = random.randint(10000,99999)
#     port = random.randint(20000,65000)

#     if random.random() < 0.75:
#         line = f"{ts_str} server sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2\n"
#     else:
#         line = f"{ts_str} server sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2\n"

#     lines.append(line)

# with open("auth.log","w") as f:
#     f.writelines(lines)

# print("500-line dataset generated.")


from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

HOST = "server"

COMMON_USERS = [
    "root", "admin", "ubuntu", "test", "guest", "user", "oracle", "postgres",
    "nginx", "deploy", "backup", "dev", "ops", "alice", "bob", "charlie",
    "yaman", "ec2-user", "ftp", "mysql"
]

NORMAL_USERS = ["alice", "bob", "charlie", "yaman", "dev", "ops", "ubuntu"]
ATTACK_USERS = [
    "root", "admin", "test", "guest", "ubuntu", "oracle", "postgres",
    "ftp", "mysql", "backup", "deploy", "devops", "ansible", "jenkins"
]

NORMAL_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30",
    "10.0.0.5", "10.0.0.10", "172.16.1.15"
]

ATTACK_IPS = [
    "185.234.217.12", "45.67.89.10", "103.45.67.89", "198.51.100.23"
]

RANDOM_COMMANDS = [
    "/usr/bin/id",
    "/bin/cat /etc/shadow",
    "/usr/bin/whoami",
    "/bin/ls /root",
    "/usr/bin/systemctl restart ssh",
    "/usr/bin/journalctl -xe"
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


def sudo_command(dt: datetime, username: str, tty: str = "pts/0") -> str:
    cmd = random.choice(RANDOM_COMMANDS)
    return (
        f"{ts_str(dt)} {HOST} sudo:    {username} : "
        f"TTY={tty} ; PWD=/home/{username} ; USER=root ; COMMAND={cmd}"
    )


def sudo_auth_failure(dt: datetime, username: str, tty: str = "/dev/pts/0") -> str:
    return (
        f"{ts_str(dt)} {HOST} sudo: pam_unix(sudo:auth): authentication failure; "
        f"logname={username} uid=1000 euid=0 tty={tty} ruser={username} rhost=  user={username}"
    )


def add_normal_background(lines: list[str], start: datetime, count: int) -> None:
    """
    Add normal mixed login activity during business hours.
    """
    current = start
    for _ in range(count):
        current += timedelta(seconds=random.randint(20, 180))
        ip = random.choice(NORMAL_IPS)
        user = random.choice(NORMAL_USERS)

        roll = random.random()
        if roll < 0.60:
            lines.append(ssh_accepted_password(current, ip, user))
        elif roll < 0.80:
            lines.append(ssh_accepted_publickey(current, ip, user))
        else:
            # a little benign failure noise
            if random.random() < 0.5:
                lines.append(ssh_failed(current, ip, user))
            else:
                lines.append(ssh_failed_invalid_user(current, ip, random.choice(ATTACK_USERS)))


def add_brute_force(lines: list[str], base: datetime, ip: str, attempts: int = 8) -> None:
    """
    T1110: 5+ failed logins from same IP within 60 seconds.
    """
    users = ["root", "admin", "root", "ubuntu", "root", "test", "root", "guest", "admin", "root"]
    current = base
    for i in range(attempts):
        current += timedelta(seconds=random.randint(3, 8))
        username = users[i % len(users)]
        lines.append(ssh_failed(current, ip, username))


def add_credential_stuffing(lines: list[str], base: datetime, ip: str, usernames: int = 12) -> None:
    """
    T1078-style suspicious valid account attempt pattern:
    many distinct usernames from one IP using failed password lines.
    """
    current = base
    chosen = ATTACK_USERS[:]
    random.shuffle(chosen)
    selected = chosen[:usernames]

    for username in selected:
        current += timedelta(seconds=random.randint(2, 5))
        if random.random() < 0.35:
            lines.append(ssh_failed_invalid_user(current, ip, username))
        else:
            lines.append(ssh_failed(current, ip, username))


def add_privilege_escalation(lines: list[str], base: datetime, username: str) -> None:
    """
    T1548 test pattern:
    sudo usage followed by sudo authentication failure in same session.
    """
    lines.append(sudo_command(base + timedelta(seconds=5), username, tty="pts/1"))
    lines.append(sudo_auth_failure(base + timedelta(seconds=9), username, tty="/dev/pts/1"))


def add_off_hours_login(lines: list[str], base: datetime, ip: str, username: str) -> None:
    """
    Successful login outside 08:00-18:00.
    """
    if random.random() < 0.5:
        lines.append(ssh_accepted_password(base, ip, username))
    else:
        lines.append(ssh_accepted_publickey(base, ip, username))


def build_dataset() -> list[str]:
    random.seed(42)

    lines: list[str] = []

    # Normal baseline during business hours
    workday_start = datetime(2024, 3, 14, 8, 15, 0)
    add_normal_background(lines, workday_start, count=120)

    # T1110 brute force campaign
    brute_force_start = datetime(2024, 3, 14, 10, 5, 0)
    add_brute_force(lines, brute_force_start, ip="185.234.217.12", attempts=9)

    # More normal traffic
    add_normal_background(lines, datetime(2024, 3, 14, 10, 20, 0), count=60)

    # T1078 credential stuffing / password spraying style failed attempts
    stuffing_start = datetime(2024, 3, 14, 11, 40, 0)
    add_credential_stuffing(lines, stuffing_start, ip="45.67.89.10", usernames=12)

    # More normal traffic
    add_normal_background(lines, datetime(2024, 3, 14, 12, 30, 0), count=70)

    # T1548 sudo usage followed by auth failure
    priv_esc_start = datetime(2024, 3, 14, 14, 10, 0)
    add_privilege_escalation(lines, priv_esc_start, username="yaman")
    add_privilege_escalation(lines, datetime(2024, 3, 14, 15, 5, 0), username="dev")

    # More normal traffic
    add_normal_background(lines, datetime(2024, 3, 14, 15, 20, 0), count=70)

    # Off-hours successful logins
    add_off_hours_login(lines, datetime(2024, 3, 14, 2, 11, 40), "203.0.113.10", "alice")
    add_off_hours_login(lines, datetime(2024, 3, 14, 23, 45, 12), "198.51.100.77", "bob")
    add_off_hours_login(lines, datetime(2024, 3, 14, 6, 20, 5), "198.51.100.88", "charlie")

    # A little extra noise around attacks
    add_normal_background(lines, datetime(2024, 3, 14, 16, 0, 0), count=90)

    # Sort by timestamp string parsed back to datetime
    def parse_line_dt(line: str) -> datetime:
        prefix = " ".join(line.split()[:3])
        return datetime.strptime(f"{prefix} 2024", "%b %d %H:%M:%S %Y")

    lines.sort(key=parse_line_dt)
    return lines


def main() -> None:
    output_dir = Path("sample_logs")
    output_dir.mkdir(parents=True, exist_ok=True)

    lines = build_dataset()
    out_file = output_dir / "auth.log"

    out_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Wrote {len(lines)} lines to {out_file}")
    print("\nIncluded scenarios:")
    print("- Brute force (T1110)")
    print("- Credential stuffing / password spraying style failed attempts (T1078 test rule)")
    print("- Privilege escalation-related sudo auth failure sequence (T1548)")
    print("- Off-hours successful logins")


if __name__ == "__main__":
    main()