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


def analyze_logs(df):
    print("\n=== EVENT COUNTS ===")
    print(df["event"].value_counts())

    print("\n=== FAILED LOGINS BY SOURCE IP ===")
    failed_logins = df[df["event"] == "LOGIN_FAILED"]
    print(failed_logins["source_ip"].value_counts())

    print("\n=== FAILED LOGINS BY USERNAME ===")
    print(failed_logins["username"].value_counts())

    print("\n=== UNIQUE USERNAMES TARGETED BY SOURCE IP ===")
    usernames_by_ip = failed_logins.groupby("source_ip")["username"].nunique()
    print(usernames_by_ip.sort_values(ascending=False))


if __name__ == "__main__":
    logs = load_logs(LOG_FILE)

    print("\n=== TOTAL EVENTS ===")
    print(len(logs))

    analyze_logs(logs)
