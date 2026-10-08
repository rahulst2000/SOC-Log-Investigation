import pandas as pd

LOG_FILE = "data/ssh_auth.log"

LOG_COLUMNS = [
    "timestamp",
    "source_ip",
    "username",
    "protocol",
    "event",
    "destination_port"
]


def load_logs(file_path):
    df = pd.read_csv(
        file_path,
        names=LOG_COLUMNS,
        skip_blank_lines=True
    )

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        format="%Y-%m-%dT%H:%M:%S"
    )

    return df


def extract_iocs(df):
    failed = df[df["event"] == "LOGIN_FAILED"]

    source_ips = sorted(
        failed["source_ip"].unique()
    )

    usernames = sorted(
        failed["username"].unique()
    )

    destination_ports = sorted(
        df["destination_port"].unique()
    )

    return {
        "source_ips": source_ips,
        "usernames": usernames,
        "destination_ports": destination_ports
    }


if __name__ == "__main__":
    logs = load_logs(LOG_FILE)

    iocs = extract_iocs(logs)

    print("\n=== INDICATORS OF COMPROMISE / INVESTIGATION ===")

    print("\nSource IPs:")
    for ip in iocs["source_ips"]:
        print(f"- {ip}")

    print("\nTargeted usernames:")
    for username in iocs["usernames"]:
        print(f"- {username}")

    print("\nDestination ports:")
    for port in iocs["destination_ports"]:
        print(f"- {port}")
