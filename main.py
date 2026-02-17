from openai import OpenAI
from models import Autonomous_Security
from utils import utils
from pathlib import Path
import sys
import time
import logging
import config

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    OPENAI_API_KEY = config.OpenAI_API_KEY
except:
    import os
    from dotenv import load_dotenv
    load_dotenv()
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    

# Setting up basic logging outputs
logging.basicConfig(
    level=logging.INFO,  # Change to DEBUG if needed
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger(__name__)

# Main prompts
ppIn = Path(__file__).resolve().parent / "prompts" / "prompt1In.txt"
ppOut = Path(__file__).resolve().parent / "prompts" / "prompt1Out.txt"
p2IN = Path(__file__).resolve().parent / "prompts" / "ICL.txt"

promptIn = ppIn.read_text(encoding="utf-8")
promptOut = ppOut.read_text(encoding="utf-8")
prompt2In = p2IN.read_text(encoding="utf-8")

def main():
    openai_client = OpenAI(api_key=OPENAI_API_KEY)
    print("Hello from soc-assistant!")

    total_tally = 0
    total_counter = 0

    while True:
        logger.info("Security Test Starting")

        X, Y = utils.get_data(
            test_split=True, 
            validation_split=True, 
            small_subset=True
            )
        
        #Dataframe for training model to identify Vulnerability scans and DNS Beaconing
        VulnScanANDdnsBeacon = X["train"].head().filter(items=[
            "Src IP dec", "Src Port", "Dst IP dec", "Dst Port", 
            "Protocol", "Timestamp", "Flow Duration", 
            "Total Fwd Packet", "Total Bwd packets", 
            "SYN Flag Count", "ACK Flag Count", "RST Flag Count",
            "FIN Flag Count"])
        
        checker = Y["train"].head()

        tally = 0
        counter = 0

        logger.info("AI On")

        # Keeps track of AI call time
        start_time = time.time()

        # Catches any misinputs or crashes
        try:
            check = Autonomous_Security.openai_risk_filter(
                openai_client,
                VulnScanANDdnsBeacon,
                prompt2In,
                promptOut
            )
        except Exception:
            logger.exception("OpenAI call failed")
            time.sleep(10)
            continue

        duration = time.time() - start_time
        logger.info("OpenAI call took %.2f seconds", duration)
        print("\n")

        for timestamp, item in check:
            counter += 1
            try:
                yLabel = checker.loc[
                    checker["Timestamp"] ==  timestamp, 
                    "Label"].iloc[0]
            except Exception:
                yLabel = "Unknown"

                logger.warning("Timestamp mismatch for %s", timestamp)

            xBlacklist = item.blacklist

            # Easier to change what correct is
            correct = (
                (yLabel == "BENIGN" and not xBlacklist) or
                (yLabel != "BENIGN" and xBlacklist)
            )

            # Counts correct and incorrect attempts by the AI and logs
            # incorrect choices
            if(correct):
                tally += 1
                counter += 1
            else:
                counter += 1
                logger.warning(
                    "MISCLASSIFICATION | Timestamp=%s | True=%s | "
                    "Blacklist=%s | Risk=%s | Rationale=%s",
                    timestamp,
                    yLabel,
                    xBlacklist,
                    item.risk,
                    item.rationale
                )
            print("It was " + yLabel + 
                  ". Model quantified it's blacklist as: " + 
                  str(xBlacklist))
            print(f"{timestamp} -> {item} \n")
            
        # Accuracy report for current session
        print("Total Correct: " + str(tally) + "/" + str(counter))
        logger.info("Batch Accuracy: %.2f%% (%d/%d)",
                    tally/counter * 100, tally, counter)
        
        # Accuracy report for ALL TIME 
        total_tally = total_tally + tally
        total_counter = total_counter + counter
        print("\nAll Time Correct: " + str(total_tally) + "/" + str(total_counter)) 
        logger.info("All-Time Accuracy: %.2f%% (%d/%d)",
                    total_tally/total_counter * 100,
                    total_tally,
                    total_counter)
        
        logger.info("Security Test Stopped\n")
        time.sleep(10)


if __name__ == "__main__":
    main()
