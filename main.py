from openai import OpenAI
from models import Autonomous_Security
from utils import getData
import sys
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import config
OPENAI_API_KEY = config.OpenAI_API_KEY
def main():
    print("Hello from soc-assistant!")
    while True:
        print("Security Test Starting: \n")
        X, Y = getData.get_data(test_split=True, validation_split=True, small_subset=True)
        network_logs = X["train"].iloc[1].to_dict() #First line as a test for now
        #Dataframe for training model to identify Vulnerability scans and DNS Beaconing
        VulnScanANDdnsBeacon = X["train"].filter(items=["Src IP dec", "Dst Port", "Protocol", "Timestamp", "Flow Duration"])
        checker = Y["train"]
        tally = 0
        counter = 0
        openai_client = OpenAI(api_key=OPENAI_API_KEY)
        check = Autonomous_Security.openai_risk_filter(openai_client, VulnScanANDdnsBeacon)
        print("\n")
        for timestamp, items in check.items():
            yLabel = checker.loc[checker["Timestamp"] ==  timestamp, "Label"].iloc[0]
            xBlacklist = items.blacklist
            if((yLabel == "BENIGN" and xBlacklist == True) or (yLabel == "Portscan" and xBlacklist == False) or (yLabel == "Infiltration - Portscan" and xBlacklist == False) or (yLabel == "Botnet" and xBlacklist == False)):
                counter = counter + 1
            else:
                tally = tally + 1
                counter = counter + 1
            print("It was " + yLabel + ". Model quantified it's blacklist as: " + str(xBlacklist) + "\n")
            print(f"{timestamp} -> {items} \n")
        
        print("Total Correct: " + str(tally) + "/" + str(counter)) 
        print("Security Test Stopped: \n")
        time.sleep(10)


if __name__ == "__main__":
    main()
