from datasets import load_dataset
from pandas import DataFrame
from typing import Tuple

"""
Use like this:

from getData import get_data
X, Y = get_data(test_split=True, validation_split=True, small_subset=True)
"""

def get_data(test_split=False, validation_split=False, small_subset=False) -> Tuple[DataFrame, DataFrame]:
    """
    Function gets network traffic data from the CICIDS-2017 dataset, 
    with options for test and validation splits, 
    as well as a small subset for quick experimentation.
    """
    if validation_split and not test_split:
        raise ValueError("Validation split cannot be created without a test split.")

    ds = load_dataset("bvk/CICIDS-2017", split="train")

    if small_subset:
        ds = ds.shuffle(seed=42).select(range(1000))
    if test_split:
        ds = ds.train_test_split(test_size=0.2, seed=42)
        if validation_split:
            ds["train"], ds["validation"] = ds["train"].train_test_split(test_size=0.25, seed=42).values()

    # Normalize to a dict of splits so downstream code is consistent
    if not isinstance(ds, dict):
        ds = {"train": ds}

    X, Y = {}, {}
    for split_name, split_ds in ds.items():
        pdf = split_ds.to_pandas()
        X[split_name] = pdf.drop(columns=["Label", "Attempted Category"], errors="ignore")
        Y[split_name] = pdf.filter(["Label", "Timestamp"])

    return X, Y

if __name__ == "__main__":
    # Example usage
    X, Y = get_data(test_split=True, validation_split=True, small_subset=True)
    print(X["train"].head()) # Contains the features of the training set
    print(Y["train"].head()) # Contains the labels of the training set

