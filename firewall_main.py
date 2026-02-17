from Firewall_Rules import firewall_rules
from utils import utils
import ipaddress
from models import firewall_AI
import sys
from pathlib import Path
from openai import OpenAI
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import config

OPENAI_API_KEY = config.OpenAI_API_KEY

from pathlib import Path

SOC_ASSISTANT_ROOT = Path(__file__).resolve().parents[1]  # folder containing test_firewall_rules.py

promptIn = (SOC_ASSISTANT_ROOT  / "SOC-Assistant" / "prompts" / "prompt1In.txt").read_text(encoding="utf-8")
firewall_table_path = SOC_ASSISTANT_ROOT / "SOC-Assistant" / "prompts" / "firewall_rules.csv"
firewall_table_df = pd.read_csv(firewall_table_path)


def firewall_test():
    openai_client = OpenAI(api_key=OPENAI_API_KEY)
    internal = [ipaddress.IPv4Address(134610945), ipaddress.IPv4Address(3232238130), ipaddress.IPv4Address(3232238094)]
    flagged_IP = ipaddress.IPv4Address(134219268)
    flagged_port = 23
    flagged_protocol = 17
    
    x=True
    while x:
        X, Y = utils.get_data(
            test_split=True, 
            validation_split=True, 
            small_subset=True
            )
        #Dataframe for training model to identify Vulnerability scans and DNS Beaconing
        df = X["train"].head(100).filter(items=[
             "Src IP dec", "Src Port", "Dst IP dec", "Dst Port", 
             "Protocol","ACK Flag Count", "Label"])
        
        result = firewall_rules(df, internal, firewall_table_df)
        print(result)

        check = firewall_AI.openai_risk_filter(
                openai_client,
                df,
                promptIn
            )
        
        for i, item in enumerate(check, start=0):
            print(f"\nItem {i+1}")
            print("\nRule:", item.rule_set)
            print("\nIssue:", item.issue)
            print("\nMissed Attacks:", item.attacks)
            print("\nFix:", item.rationale_and_fix)
            print("\nCode:", item.code)

        x = False

if __name__ == "__main__":
    firewall_test()

