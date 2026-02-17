from openai import OpenAI
from models import soc_assistant
from utils import utils
from pathlib import Path
import sys
import config
import os
from dotenv import load_dotenv
load_dotenv()

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    OPENAI_API_KEY = config.OpenAI_API_KEY
except Exception:
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

def simulation(n: int, prompt_file_name: str, *, attack_types: list[str] | None = ["BENIGN", "DDoS", "Portscan", "BruteForce", "Botnet"]):
    """
    This function takes n random rows of the balanced subset (balanced 50/50 attack vs. benign)
    Asks the model to classify rows based on information from ONLY the row

    Currently works quite well for BENIGN and Portscans, not so well for other attacks
    """
    pIN = Path(__file__).resolve().parent / "prompts" / prompt_file_name
    promptIn = pIN.read_text(encoding="utf-8")

    openai_client = OpenAI(api_key=OPENAI_API_KEY)
    print("Hello from soc-assistant!")

    allowed_labels = ["BENIGN", "DDoS", "Portscan", "BruteForce", "Botnet"] # Portscan WAY over-representative
    for label in attack_types:
        if label not in allowed_labels:
            raise KeyError
        
    X, Y = utils.get_balanced_subset(
        allowed_labels=attack_types
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
    true_pos, true_neg, false_pos, false_neg = 0, 0, 0, 0


    for i, (_, row) in enumerate(flow_rows.iterrows()):
        check = soc_assistant.openai_risk_filter(
            openai_client,
            row.to_dict(),
            promptIn,
        )

        result_label = check.attack_type
        gt_label = labels.iloc[i]
        if gt_label == result_label:
            if gt_label == "BENIGN":
                true_neg += 1
            else:
                true_pos += 1
            correct += 1
        else:
            if gt_label == "BENIGN":
                false_pos += 1
            else:
                false_neg += 1
        total += 1

        print(f"Network Flow Data {i}:\nGround Truth: {gt_label}\nLLM Result: {result_label}\n")
    
    accuracy = (correct / total) * 100 if total != 0 else 0
    precision = true_pos / (true_pos + false_pos) if (true_pos + false_pos) != 0 else 0
    recall = true_pos / (true_pos + false_neg) if (true_pos + false_neg) != 0 else 0
    print(f"Accuracy: {round(accuracy, 4)}%")
    print(f"True Positives: {true_pos} | True Negatives: {true_neg} | False Positive: {false_pos} | False Negatives: {false_neg}")
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) != 0 else 0
    print(f"Precision: {round(precision, 4)} | Recall: {round(recall, 4)} | F1: {round(f1, 4)}")




def sim_w_history(n: int, window: float, hist_prompt: str, no_hist_prompt: str, attack_types: list[str] | None = ["BENIGN", "DDoS", "Portscan", "BruteForce", "Botnet"]):
    """
    This function takes n random rows from a balanced subset of the dataset.
    Subset is balanced by attack_types, should be 50/50 Benign vs non-benign
    For each row, it collects some important statistics about what happened in 
        that row during given time window in seconds
    It currently does not work very well.
    """
    pIN = Path(__file__).resolve().parent / "prompts" / no_hist_prompt
    pHIST = Path(__file__).resolve().parent / "prompts" / hist_prompt

    pI = pIN.read_text(encoding="utf-8")
    pH = pHIST.read_text(encoding="utf-8")

    openai_client = OpenAI(api_key=OPENAI_API_KEY)
    print("Hello from soc-assistant!")

    allowed_labels = ["BENIGN", "DDoS", "Portscan", "BruteForce", "Botnet"] # Portscan WAY over-representative
    for label in attack_types:
        if label not in allowed_labels:
            raise KeyError

    X, Y = utils.get_balanced_subset(
        allowed_labels=attack_types
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
    true_pos, true_neg, false_pos, false_neg = 0, 0, 0, 0

    for i, (_, row) in enumerate(flow_rows.iterrows()):
        row = utils.get_history(flow_rows, row, window)
        promptIn = pI if row.get("no_history") else pH

        check = soc_assistant.openai_risk_filter(
            openai_client,
            row.to_dict(),
            promptIn,
        )

        result_label = check.attack_type
        gt_label = labels.iloc[i]
        if gt_label == result_label:
            if gt_label == "BENIGN":
                true_neg += 1
            else:
                true_pos += 1
            correct += 1
        else:
            if gt_label == "BENIGN":
                false_pos += 1
            else:
                false_neg += 1
        total += 1

        print(f"Network Flow Data {i}:\nGround Truth: {gt_label}\nLLM Result: {result_label}\n")
    
    accuracy = (correct / total) * 100 if total != 0 else 0
    precision = true_pos / (true_pos + false_pos) if (true_pos + false_pos) != 0 else 0
    recall = true_pos / (true_pos + false_neg) if (true_pos + false_neg) != 0 else 0
    print(f"Accuracy: {round(accuracy, 4)}%")
    print(f"True Positives: {true_pos} | True Negatives: {true_neg} | False Positive: {false_pos} | False Negatives: {false_neg}")
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) != 0 else 0
    print(f"Precision: {round(precision, 4)} | Recall: {round(recall, 4)} | F1: {round(f1, 4)}")
        

if __name__ == "__main__":
    simulation(5, "aggressive.txt")
    # sim_w_history(5, 600, "aggressive_hist.txt", "aggressive.txt")
