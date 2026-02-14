from datasets import load_dataset
import pandas as pd
from pandas import DataFrame
from typing import Tuple
import random

def get_data(test_split=False, validation_split=False, small_subset=False) -> Tuple[DataFrame, DataFrame]:
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

    if small_subset:
        ds = ds.shuffle(seed=seed).select(range(1000))
    if test_split:
        ds = ds.train_test_split(test_size=0.2, seed=seed)
        if validation_split:
            ds["train"], ds["validation"] = ds["train"].train_test_split(test_size=0.25, seed=seed).values()

    # Normalize to a dict of splits so downstream code is consistent
    if not isinstance(ds, dict):
        ds = {"train": ds}

    X, Y = {}, {}
    running_id = 0
    for split_name, split_ds in ds.items():
        pdf = split_ds.to_pandas().reset_index(drop=True)
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



if __name__ == "__main__":
    # Example usage
    # X, Y = get_data(test_split=True, validation_split=True, small_subset=True)
    # print(X["train"].head()) # Contains the features of the training set
    # print(Y["train"].head()) # Contains the labels of the training set

    print(count_attacks("00:00", "59:59.9"))
