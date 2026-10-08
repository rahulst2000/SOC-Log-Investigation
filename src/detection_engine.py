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

BRUTE_FORCE_THRESHOLD = 5
PASSWORD_SPRAY_THRESHOLD = 3
TIME_WINDOW_MINUTES = 5


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


def detect_brute_force(df):
    failed = df[df["event"] == "LOGIN_FAILED"].copy()

    alerts = []

    for (source_ip, username), group in failed.groupby(
        ["source_ip", "username"]
    ):
        group = group.sort_values("timestamp")

        for i in range(len(group)):
            start_time = group.iloc[i]["timestamp"]
            end_time = start_time + pd.Timedelta(
                minutes=TIME_WINDOW_MINUTES
            )

            window = group[
                (group["timestamp"] >= start_time) &
                (group["timestamp"] <= end_time)
            ]

            if len(window) >= BRUTE_FORCE_THRESHOLD:
                alerts.append({
                    "type": "BRUTE_FORCE",
                    "source_ip": source_ip,
                    "username": username,
                    "attempts": len(window),
                    "start_time": start_time,
                    "end_time": window.iloc[-1]["timestamp"]
                })
                break

    return alerts


def detect_password_spraying(df):
    failed = df[df["event"] == "LOGIN_FAILED"].copy()

    alerts = []

    for source_ip, group in failed.groupby("source_ip"):
        group = group.sort_values("timestamp")

        for i in range(len(group)):
            start_time = group.iloc[i]["timestamp"]
            end_time = start_time + pd.Timedelta(
                minutes=TIME_WINDOW_MINUTES
            )

            window = group[
                (group["timestamp"] >= start_time) &
                (group["timestamp"] <= end_time)
            ]

            unique_users = window["username"].nunique()

            if unique_users >= PASSWORD_SPRAY_THRESHOLD:
                alerts.append({
                    "type": "PASSWORD_SPRAYING",
                    "source_ip": source_ip,
                    "unique_users": unique_users,
                    "start_time": start_time,
                    "end_time": window.iloc[-1]["timestamp"]
                })
                break

    return alerts


def detect_failure_then_success(df):
    alerts = []

    for (source_ip, username), group in df.groupby(
        ["source_ip", "username"]
    ):
        group = group.sort_values("timestamp")

        for i in range(len(group)):
            current_event = group.iloc[i]

            if current_event["event"] != "LOGIN_SUCCESS":
                continue

            success_time = current_event["timestamp"]
            start_time = success_time - pd.Timedelta(
                minutes=TIME_WINDOW_MINUTES
            )

            previous_events = group[
                (group["timestamp"] >= start_time) &
                (group["timestamp"] < success_time)
            ]

            failed_attempts = previous_events[
                previous_events["event"] == "LOGIN_FAILED"
            ]

            if len(failed_attempts) >= 3:
                alerts.append({
                    "type": "FAILURE_THEN_SUCCESS",
                    "source_ip": source_ip,
                    "username": username,
                    "failed_attempts": len(failed_attempts),
                    "success_time": success_time
                })
                break

    return alerts


if __name__ == "__main__":
    logs = load_logs(LOG_FILE)

    brute_force_alerts = detect_brute_force(logs)
    password_spray_alerts = detect_password_spraying(logs)
    failure_success_alerts = detect_failure_then_success(logs)

    print("\n=== BRUTE FORCE ALERTS ===")
    for alert in brute_force_alerts:
        print(alert)

    print("\n=== PASSWORD SPRAYING ALERTS ===")
    for alert in password_spray_alerts:
        print(alert)

    print("\n=== FAILURE THEN SUCCESS ALERTS ===")
    for alert in failure_success_alerts:
        print(alert)
