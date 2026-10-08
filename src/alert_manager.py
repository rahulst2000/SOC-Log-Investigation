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


def create_alert(
    alert_type,
    source_ip,
    username=None,
    attempts=None,
    unique_users=None,
    failed_attempts=None,
    success_time=None,
    severity="MEDIUM"
):
    alert = {
        "alert_type": alert_type,
        "source_ip": source_ip,
        "username": username,
        "attempts": attempts,
        "unique_users": unique_users,
        "failed_attempts": failed_attempts,
        "success_time": success_time,
        "severity": severity,
        "status": "OPEN"
    }

    return alert


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
                alert = create_alert(
                    alert_type="BRUTE_FORCE",
                    source_ip=source_ip,
                    username=username,
                    attempts=len(window),
                    severity="HIGH"
                )

                alerts.append(alert)
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
                alert = create_alert(
                    alert_type="PASSWORD_SPRAYING",
                    source_ip=source_ip,
                    unique_users=unique_users,
                    severity="HIGH"
                )

                alerts.append(alert)
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
                alert = create_alert(
                    alert_type="FAILURE_THEN_SUCCESS",
                    source_ip=source_ip,
                    username=username,
                    failed_attempts=len(failed_attempts),
                    success_time=success_time,
                    severity="CRITICAL"
                )

                alerts.append(alert)
                break

    return alerts


def generate_alerts(df):
    alerts = []

    alerts.extend(detect_brute_force(df))
    alerts.extend(detect_password_spraying(df))
    alerts.extend(detect_failure_then_success(df))

    return alerts


if __name__ == "__main__":
    logs = load_logs(LOG_FILE)

    alerts = generate_alerts(logs)

    print("\n=== SOC ALERTS ===")

    for number, alert in enumerate(alerts, start=1):
        print(f"\nAlert ID: ALERT-{number:03d}")

        for key, value in alert.items():
            print(f"{key}: {value}")
