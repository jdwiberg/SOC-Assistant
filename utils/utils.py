from datasets import load_dataset
import pandas as pd
from pandas import DataFrame
from typing import Tuple
import random

def get_data(
    test_split=False,
    validation_split=False,
    small_subset=False,
    allowed_labels: list[str] | None = None,
) -> Tuple[DataFrame, DataFrame]:
    """
    Function gets network traffic data from the CICIDS-2017 dataset, 
    with options for test and validation splits, 
    as well as a small subset for quick experimentation.
    
    Use like this:

    from getData import get_data
    X, Y = get_data(test_split=True, validation_split=True, small_subset=True)
    """
    if validation_split and not test_split:
        raise ValueError("Validation split cannot be created without a test split.")

    ds = load_dataset("bvk/CICIDS-2017", split="train")
    seed = random.randint(1, 255)

    label_map = {
        "BENIGN": "BENIGN",

        "Botnet": "Botnet",
        "Botnet - Attempted": "Botnet",

        "DDoS": "DoS",

        "DoS GoldenEye": "DoS",
        "DoS GoldenEye - Attempted": "DoS",
        "DoS Hulk": "DoS",
        "DoS Hulk - Attempted": "DoS",
        "DoS Slowhttptest": "DoS",
        "DoS Slowhttptest - Attempted": "DoS",
        "DoS Slowloris": "DoS",
        "DoS Slowloris - Attempted": "DoS",

        "FTP-Patator": "BruteForce",
        "FTP-Patator - Attempted": "BruteForce",
        "SSH-Patator": "BruteForce",

        "Heartbleed": "Botnet",

        "Infiltration": "Portscan",
        "Infiltration - Attempted": "Portscan",
        "Infiltration - Portscan": "Portscan",

        "Portscan": "Portscan",
    }

    ds = ds.shuffle(seed=seed).select(range(40000))
    if small_subset:
        ds = ds.select(range(1000))
    if test_split:
        ds = ds.train_test_split(test_size=0.2, seed=seed)
        if validation_split:
            ds["train"], ds["validation"] = ds["train"].train_test_split(test_size=0.25, seed=seed).values()

    # Normalize to a dict of splits so downstream code is consistent
    if not isinstance(ds, dict):
        ds = {"train": ds}

    X, Y = {}, {}
    if allowed_labels is None:
        allowed_labels = ["BENIGN", "DoS", "Portscan", "BruteForce"]
    allowed_set = set(allowed_labels)
    
    running_id = 0
    for split_name, split_ds in ds.items():
        pdf = split_ds.to_pandas().reset_index(drop=True)

        pdf["Label"] = pdf["Label"].replace(label_map)
        pdf = pdf[pdf["Label"].isin(allowed_set)].reset_index(drop=True)

        pdf["Timestamp"] = pdf["Timestamp"].apply(to_seconds)

        pdf["id"] = range(running_id, running_id + len(pdf))
        running_id += len(pdf)
        X[split_name] = pdf.drop(columns=["Label", "Attempted Category"], errors="ignore")
        Y[split_name] = pdf.filter(["id", "Label", "Timestamp", "Attempted Category"])
    return X, Y


def to_seconds(ts: str) -> float:
    minutes, seconds = ts.split(":")
    return int(minutes) * 60 + float(seconds)


def get_timeframe(start: str, end: str) -> DataFrame:
    """
    Use form '00:00.0', '59:59.9'
    """
    
    X, Y = get_data()
    X = X["train"]
    Y = Y["train"]

    start, end = to_seconds(start), to_seconds(end)
    X["time"] = X["Timestamp"].apply(to_seconds)

    X["time"] = pd.to_timedelta(X["time"])
    filtered_X = X[
        X["time"].between(
            pd.to_timedelta(start),
            pd.to_timedelta(end)
        )
    ]

    filtered_Y = Y[Y["id"].isin(filtered_X["id"])]
    filtered_Y = (
        filtered_Y.set_index("id")
        .reindex(filtered_X["id"])
        .reset_index()
    )

    return filtered_X, filtered_Y


def count_attacks(start: str, end: str, *, Y_timeframe: DataFrame | None = None) -> int:
    if not Y_timeframe:
        X, Y_timeframe = get_timeframe(start, end)

    return len(Y_timeframe[(Y_timeframe["Label"] != "BENIGN")])

def ip_hist(df: pd.DataFrame, start: float, window: float, src_ip: str, dst_ip):
    # Get all rows from the df where "Src IP dec" = src_ip
    # and (start - window) < "Timestamp" < start

    null = pd.Series(
        {
            "no_history": 1
        }
    )

    start_window = start - window
    src_mask = (
        (df["Src IP dec"] == src_ip)
        & (df["Timestamp"] >= start_window)
        & (df["Timestamp"] < start)
    )
    dst_mask = (
        (df["Dst IP dec"] == dst_ip)
        & (df["Timestamp"] >= start_window)
        & (df["Timestamp"] < start)
    )

    rows = df.loc[src_mask].copy()
    rows_dst = df.loc[dst_mask].copy()
    
    if len(rows) == 0:
        return null

    src_flow_count_w = len(rows)
    src_unique_dst_count_w = rows["Dst IP dec"].nunique()
    src_unique_dst_port_count_w = rows["Dst Port"].nunique()
    src_syn_count_w = rows["SYN Flag Count"].sum()
    src_bytes_fwd_sum_w = rows["Total Length of Fwd Packet"].sum()
    src_bytes_bwd_sum_w = rows["Total Length of Bwd Packet"].sum()

    total_bwd_packets = rows["Total Bwd packets"]
    ack = rows["ACK Flag Count"]
    syn = rows["SYN Flag Count"]
    rst = rows["RST Flag Count"]
    low_bwd_bytes = rows["Total Length of Bwd Packet"]

    failedish_mask = (
        (total_bwd_packets == 0)
        | ((ack == 0) & (syn > 0))
        | ((rst > 0) & (low_bwd_bytes == 0))
    )
    src_failedish_proxy_w = int(failedish_mask.sum()) if hasattr(failedish_mask, "sum") else 0

    dst_flow_count_w = len(rows_dst)
    dst_unique_src_count_w = rows_dst["Src IP dec"].nunique()
    dst_syn_count_w = rows_dst["SYN Flag Count"].sum()

    dst_bytes_fwd_sum_w = rows_dst["Total Length of Fwd Packet"].sum()
    dst_bytes_bwd_sum_w = rows_dst["Total Length of Bwd Packet"].sum()
    dst_bytes_sum_w = dst_bytes_bwd_sum_w + dst_bytes_fwd_sum_w

    return pd.Series(
        {
            "src_flow_count_w": int(src_flow_count_w),
            "src_unique_dst_count_w": int(src_unique_dst_count_w),
            "src_unique_dst_port_count_w": int(src_unique_dst_port_count_w),
            "src_syn_count_w": float(src_syn_count_w),
            "src_bytes_fwd_sum_w": float(src_bytes_fwd_sum_w),
            "src_bytes_bwd_sum_w": float(src_bytes_bwd_sum_w),
            "src_failedish_proxy_w": int(src_failedish_proxy_w),
            "dst_flow_count_w": int(dst_flow_count_w),
            "dst_unique_src_count_w": int(dst_unique_src_count_w),
            "dst_syn_count_w": float(dst_syn_count_w),
            "dst_bytes_sum_w": float(dst_bytes_sum_w)
        }
    )


def get_history(rows: pd.DataFrame, row: pd.Series, window: float):
    src_ip = row.get("Src IP dec")
    dst_ip = row.get("Dst IP dec")
    start = row.get('Timestamp')

    new = ip_hist(rows, start, window, src_ip, dst_ip)
    row = pd.concat([row, new])

    return row

def get_balanced_subset(
    *,
    X: dict[str, DataFrame] | None = None,
    Y: dict[str, DataFrame] | None = None,
    seed: int | None = None,
    allowed_labels: list[str] | None = None,
) -> Tuple[DataFrame, DataFrame]:
    """
    Returns the largest balanced subset with a 50/50 split of BENIGN vs non-BENIGN rows.
    """

    if X is None or Y is None:
        X, Y = get_data(
            test_split=False,
            validation_split=False,
            small_subset=False,
            allowed_labels=allowed_labels,
        )

    X_train = X["train"]
    Y_train = Y["train"]

    benign = Y_train[Y_train["Label"] == "BENIGN"]
    non_benign = Y_train[Y_train["Label"] != "BENIGN"]

    n_half = min(len(benign), len(non_benign))
    if n_half == 0:
        raise ValueError("Not enough rows to build a balanced subset.")

    benign_sample = benign.sample(n=n_half, random_state=seed)
    non_benign_sample = non_benign.sample(n=n_half, random_state=seed)
    subset_labels = pd.concat([benign_sample, non_benign_sample]).sample(
        frac=1.0, random_state=seed
    )

    subset_X = X_train[X_train["id"].isin(subset_labels["id"])]
    subset_X = subset_X.set_index("id").reindex(subset_labels["id"]).reset_index()
    subset_Y = subset_labels.set_index("id").reindex(subset_labels["id"]).reset_index()

    return subset_X, subset_Y



if __name__ == "__main__":
    # Example usage
    # X, Y = get_data(test_split=True, validation_split=True, small_subset=True)
    # print(X["train"].head()) # Contains the features of the training set
    # print(Y["train"].head()) # Contains the labels of the training set

    print(count_attacks("00:00", "59:59.9"))
