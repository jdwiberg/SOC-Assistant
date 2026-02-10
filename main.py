from openai import OpenAI
from models import Autonomous_Security
from utils import getData
import sys
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import config

ppIn = Path(__file__).resolve().parent / "prompts" / "prompt1In.txt"
ppOut = Path(__file__).resolve().parent / "prompts" / "prompt1Out.txt"
promptIn = ppIn.read_text(encoding="utf-8")
promptOut = ppOut.read_text(encoding="utf-8")

OPENAI_API_KEY = config.OpenAI_API_KEY
def main():
    print("Hello from soc-assistant!")
    total_tally = 0
    total_counter = 0
    while True:
        print("Security Test Starting: \n")
        X, Y = getData.get_data(test_split=True, validation_split=True, small_subset=True)
        network_logs = X["train"].iloc[1].to_dict() #First line as a test for now
        #Dataframe for training model to identify Vulnerability scans and DNS Beaconing
        VulnScanANDdnsBeacon = X["train"]
        # .filter(items=["Src IP dec", "Src Port", "Dst IP dec", "Dst Port", "Protocol", "Timestamp", "Flow Duration", "Total Fwd Packet", "Total Bwd packets"])
        checker = Y["train"]
        tally = 0
        counter = 0
        openai_client = OpenAI(api_key=OPENAI_API_KEY)
        check = Autonomous_Security.openai_risk_filter(openai_client, VulnScanANDdnsBeacon, promptIn, promptOut)
        print("\n")
        for timestamp, items in check.items():
            try:
                yLabel = checker.loc[checker["Timestamp"] ==  timestamp, "Label"].iloc[0]
            except:
                yLabel = "Unknown"
            xBlacklist = items.blacklist
            if((yLabel == "BENIGN" and xBlacklist == True) or (yLabel == "DDoS" and xBlacklist == False) or (yLabel == "Portscan" and xBlacklist == False) or (yLabel == "Infiltration - Portscan" and xBlacklist == False) or (yLabel == "Botnet" and xBlacklist == False)):
                counter = counter + 1
            else:
                tally = tally + 1
                counter = counter + 1
            print("It was " + yLabel + ". Model quantified it's blacklist as: " + str(xBlacklist))
            print(f"{timestamp} -> {items} \n")
        
        print("Total Correct: " + str(tally) + "/" + str(counter))
        total_tally = total_tally + tally
        total_counter = total_counter + counter
        print("\nAll Time Correct: " + str(total_tally) + "/" + str(total_counter)) 
        print("Security Test Stopped: \n")
        time.sleep(10)


if __name__ == "__main__":
    main()
