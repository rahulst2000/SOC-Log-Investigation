import pandas as pd
LOG_COLUMNS=[
"timestamp",
"source_ip",
"username",
"protocol",
"event",
"destination_port"
]
def load_logs(file_path):
    df=pd.read_csv(file_path,names=LOG_COLUMNS,
    skip_blank_lines=True)
    df["timestamp"]=pd.to_datetime(df["timestamp"],format="%Y-%m-%dT%H:%M:%S")
    return df
if __name__=="__main__":
    logs = load_logs("data/ssh_auth.log")
    print("\n=== SECURITY LOGS===")
    print(logs)
    print("\n= = = TOTAL EVENTS = = =")
    print(len(logs))
