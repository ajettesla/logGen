import random
from datetime import datetime, timedelta
import time
import ipaddress
import json
import argparse
import os

# Default configuration
DEFAULT_CONFIG = {
    "target_mb": 1,
    "log_file": "fake_auth.log",
    "users": ["gatewaya", "root", "nobody"],
    "hosts": ["gatewaya"],
    "ip_pools": {"local": "192.168.0.0/16", "external": "0.0.0.0/0"},
    "log_type_weights": {
        "sudo_command": 10,
        "pam_unix_session_open": 10,
        "pam_unix_session_close": 10,
        "ssh_success": 10,
        "ssh_fail": 10,
        "brute_force": 5,
        "privilege_escalation": 5,
        "insider_threat": 5
    }
}

def load_config(config_file="config.json"):
    """Load configuration from JSON file or use defaults."""
    config = DEFAULT_CONFIG.copy()
    if os.path.exists(config_file):
        with open(config_file, "r") as f:
            file_config = json.load(f)
        config.update(file_config)
        print(f"Loaded configuration from {config_file}")
    else:
        print("Using default configuration (no config.json found)")
    config["ip_pools"] = {k: ipaddress.IPv4Network(v) for k, v in config["ip_pools"].items()}
    return config

def random_ip(network):
    """Generate a random IP from a network WITHOUT enumerating all hosts."""
    net_int = int(network.network_address)
    broadcast_int = int(network.broadcast_address)
    # Avoid network and broadcast addresses if possible
    if broadcast_int - net_int <= 2:
        return str(network.network_address)
    random_int = random.randint(net_int + 1, broadcast_int - 1)
    return str(ipaddress.IPv4Address(random_int))

def next_timestamp(last_timestamp):
    """
    Given the last timestamp, return a new timestamp that is slightly later,
    adding a random small increment (up to 10 seconds + microseconds).
    """
    increment = timedelta(
        seconds=random.randint(0, 10),
        microseconds=random.randint(0, 999999)
    )
    return last_timestamp + increment

def format_log(timestamp, host, service, message):
    """Format a log entry with Splunk-compatible timestamp (no microseconds, no timezone)."""
    formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")
    return f"{formatted_time} {host} {service}: {message}\n"

def generate_log_line(config):
    """Generate a random log line based on log type weights."""
    log_types = list(config["log_type_weights"].keys())
    weights = list(config["log_type_weights"].values())
    log_type = random.choices(log_types, weights=weights, k=1)[0]
    user = random.choice(config["users"])
    host = random.choice(config["hosts"])
    local_ip = random_ip(config["ip_pools"]["local"])
    ext_ip = random_ip(config["ip_pools"]["external"])

    if log_type == "sudo_command":
        return ("sudo", f"{user} : PWD=/ ; USER={user} ; COMMAND=/usr/bin/ls")
    elif log_type == "pam_unix_session_open":
        return ("sshd[1234]", f"session opened for user {user} by (uid=0)")
    elif log_type == "pam_unix_session_close":
        return ("sshd[1234]", f"session closed for user {user}")
    elif log_type == "ssh_success":
        return ("sshd[1234]", f"Accepted password for {user} from {ext_ip} port {random.randint(1024, 65535)} ssh2")
    elif log_type == "ssh_fail":
        return ("sshd[1234]", f"Failed password for {user} from {ext_ip} port {random.randint(1024, 65535)} ssh2")
    elif log_type == "brute_force":
        return ("sshd[1234]", f"Failed password for {user} from {ext_ip} port {random.randint(1024, 65535)} ssh2")
    elif log_type == "privilege_escalation":
        return ("sudo", f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash")
    elif log_type == "insider_threat":
        return ("syslog", f"User {user} accessed sensitive file from {local_ip}")
    return ("syslog", "Generic log entry")

def generate_log_file(config):
    """Generate logs and write to file with progress updates every 5 seconds."""
    mb_limit = config["target_mb"] * 1024 * 1024  # Convert MB to bytes
    log_file = config["log_file"]
    buffer = []
    total_size = 0
    last_print_time = time.time()
    last_write_time = time.time()
    start_time = time.time()

    last_timestamp = datetime.now() - timedelta(days=30)  # Start 30 days ago

    with open(log_file, "a", encoding="utf-8") as f:
        while total_size < mb_limit:
            # Generate a new timestamp that is always later than the last
            timestamp = next_timestamp(last_timestamp)
            last_timestamp = timestamp

            host = random.choice(config["hosts"])
            service, message = generate_log_line(config)
            log = format_log(timestamp, host, service, message)
            buffer.append(log)
            total_size += len(log.encode("utf-8"))

            current_time = time.time()

            # Print progress every 5 seconds to stdout
            if current_time - last_print_time >= 5:
                print(f"Progress: {total_size / (1024 * 1024):.2f} MB written so far")
                last_print_time = current_time

            # Write buffer to file every 10 seconds and flush to ensure logging
            if current_time - last_write_time >= 10:
                f.writelines(buffer)
                f.flush()  # Force write to disk
                print(f"Wrote {len(buffer)} lines to {log_file}, total size {total_size / (1024 * 1024):.2f} MB")
                buffer = []
                last_write_time = current_time

        # Write any remaining logs in the buffer
        if buffer:
            f.writelines(buffer)
            f.flush()
            print(f"Wrote remaining {len(buffer)} lines to {log_file}, final size {total_size / (1024 * 1024):.2f} MB")

    print(f"Log generation completed in {time.time() - start_time:.2f} seconds.")

def main():
    """Parse arguments and run log generation."""
    parser = argparse.ArgumentParser(description="Generate fake auth logs.")
    parser.add_argument("--target-mb", type=int, help="Target size in MB")
    parser.add_argument("--log-file", type=str, help="Output log file name")
    args = parser.parse_args()

    config = load_config()
    if args.target_mb is not None:
        config["target_mb"] = args.target_mb
    if args.log_file:
        config["log_file"] = args.log_file

    # Clear the file before starting
    open(config["log_file"], "w", encoding="utf-8").close()
    print(f"Generating logs to {config['log_file']} with target size {config['target_mb']} MB...")
    generate_log_file(config)

if __name__ == "__main__":
    main()
