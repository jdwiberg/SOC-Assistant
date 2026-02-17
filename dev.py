from openai import OpenAI
from models import soc_assistant
from utils import utils
from pathlib import Path
import sys
import time
import logging
import config
from tqdm import tqdm
import os
from dotenv import load_dotenv
load_dotenv()

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    OPENAI_API_KEY = config.OpenAI_API_KEY
except Exception:
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    


def main(n: int):
    pIN = Path(__file__).resolve().parent / "prompts" / "prompt2in.txt"
    promptIn = pIN.read_text(encoding="utf-8")

    openai_client = OpenAI(api_key=OPENAI_API_KEY)
    print("Hello from soc-assistant!")

    X, Y = utils.get_balanced_subset(
        allowed_labels=["BENIGN", "DDoS", "PortScan", "BruteForce"]
    )
    
    #Dataframe for training model to identify Vulnerability scans and DNS Beaconing
    flow_rows = X.head(n).filter(items=[
        "Src IP dec", "Src Port", "Dst IP dec", "Dst Port", 
        "Protocol", "Timestamp", "Flow Duration", 
        "Total Fwd Packet", "Total Bwd packets", 
        "Total Length of Bwd Packet", "Total Length of Fwd Packet",
        "SYN Flag Count", "ACK Flag Count", "RST Flag Count",
        "FIN Flag Count"])
    
    labels = Y.loc[flow_rows.index, "Label"].reset_index(drop=True)

    total = 0
    correct = 0

    print("Starting")
    with tqdm(flow_rows.iterrows(), desc="Analyzing Network Flows", total=n) as pbar:
        for i, (_, row) in enumerate(pbar):
            check = soc_assistant.openai_risk_filter(
                openai_client,
                row.to_dict(),
                promptIn,
            )

            result_label = check.attack_type
            gt_label = labels.iloc[i]
            if gt_label == result_label:
                correct += 1
            total += 1

            print(f"Network Flow Data {i}:\nGround Truth: {gt_label}\nLLM Result: {result_label}")
    
    print(f"Accuracy: {round((correct / total) * 100 if total != 0 else 0, 4)}%")
        

if __name__ == "__main__":
    main(10)
