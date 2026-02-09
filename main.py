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
        openai_client = OpenAI(api_key=OPENAI_API_KEY)
        check = Autonomous_Security.openai_risk_filter(openai_client, network_logs)
        for asof, items in check.items():
            print(f"{asof} -> {items} \n")
        print("Security Test Stopped: \n")
        time.sleep(600)


if __name__ == "__main__":
    main()
