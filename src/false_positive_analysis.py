import pandas as pd

LOG_FILE = "data/ssh_auth.log"
ALLOWLIST_FILE = "data/allowlisted_ips.csv"

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


def load_allowlist(file_path):
    return pd.read_csv(file_path)


def analyze_false_positives(logs, allowlist):
    results = []

    for ip in logs["source_ip"].unique():

        matching_ip = allowlist[
            allowlist["source_ip"] == ip
        ]

        if not matching_ip.empty:

            description = matching_ip.iloc[0]["description"]

            results.append({
                "source_ip": ip,
                "classification": "FALSE_POSITIVE_CANDIDATE",
                "reason": description
            })

    return results


if __name__ == "__main__":
    logs = load_logs(LOG_FILE)
    allowlist = load_allowlist(ALLOWLIST_FILE)

    results = analyze_false_positives(
        logs,
        allowlist
    )

    print("\n=== FALSE POSITIVE ANALYSIS ===")

    if not results:
        print("No allowlisted activity identified.")

    else:
        for result in results:
            print(result)

