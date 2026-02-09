from openai import OpenAI
from pydantic import BaseModel
from typing import List, Dict, Literal
import prompts
# import sys
# from pathlib import Path
# import time

# ROOT = Path(__file__).resolve().parents[2]
# sys.path.insert(0, str(ROOT))
# import config

# OPENAI_API_KEY = config.OpenAI_API_KEY

class RiskItem(BaseModel): #Creates a new Pydantic model to structure risk assessment data
    ip_src: str
    port_dest: str  # IP Address
    risk: Literal["low", "medium", "high"] # Risk level
    network_block: bool # Whether network action was blocked by AI
    rationale: str # Rationale for the risk assessment

class RiskReport(BaseModel): #Creates a new Pydantic model to structure the overall risk report
    asof: str # Timestamp of the report, "as of" format
    items: List[RiskItem]  # List of risk items

def openai_risk_filter(openai_client: OpenAI, text) -> Dict[str, RiskItem]:
    
    system = ( #System prompt for OpenAI, Python concatenates all the strings into 1 long 'str' sentence
        "Check for bad network stuff"
    )

    user = ( #User prompt for OpenAI
        "For each item, output risk (low/medium/high), network_block(true/false), and a 1-sentence rationale. \n\n"
        f"Data:\n{text}" 
    )
    #^ Constructs the user prompt with the payload data formatted as JSON
    resp = openai_client.responses.parse(
         model="gpt-4.1-mini", #Specifies the OpenAI model to use
            input=[
                {"role": "system", "content": system}, #Sets the rules/behavior that I want to models data collection/response to abide by
                {"role": "user", "content": user}, #Gives the model the actual request and data you want it to act on
            ],
            text_format=RiskReport #Tells the OpenAI SDK to make the model's reponse mathc this Pydantic schema and parse the output into a 'RiskReport' object for me
    )
    #^ Sends the request to OpenAI and parses the response into a RiskReport object

    report: RiskReport = resp.output_parsed #Pulls the already parsed, validated results out of the OpenAI Response and stores it in report as a RiskReport Object
    #'report.items' is a list of 'RiskItem' objects
    return {item.ip_src: item for item in report.items}  #Builds and returns a dictionary that maps each IP to its 'RiskItem' object


# def main_loop() -> None:
#     while True:
#         print("Security Test Starting: \n")
#         Test_text = Path("TEST.json").read_text(encoding="utf-8")
#         openai_client = OpenAI(api_key=OPENAI_API_KEY)
#         check = openai_risk_filter(openai_client, Test_text)
#         for asof, items in check.items():
#             print(f"{asof} -> {items} \n")
#         print("Security Test Stopped: \n")
#         time.sleep(600)

# if __name__ == "__main__":
#     main_loop()
