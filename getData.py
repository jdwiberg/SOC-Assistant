from datasets import load_dataset, Dataset
from pandas import DataFrame
from typing import Tuple

def get_data(test_split=False, validation_split=False, small_subset=False) -> Tuple[DataFrame, DataFrame]:
    """
    Function gets network traffic data from the CICIDS-2017 dataset, 
    with options for test and validation splits, 
    as well as a small subset for quick experimentation.
    """

    ds = load_dataset("bvk/CICIDS-2017", split="train")

    if small_subset:
        ds = ds.shuffle(seed=42).select(range(1000))
    if test_split:
        ds = ds.train_test_split(test_size=0.2, seed=42)
    if validation_split:
        ds = ds.train_test_split(test_size=0.2, seed=42)
        ds["train"], ds["validation"] = ds["train"].train_test_split(test_size=0.25, seed=42).values()

    ds = DataFrame(ds)
    X = ds.drop(columns=["Label", "Attempted Category"])
    Y = ds["Label"]
    

    return X, Y