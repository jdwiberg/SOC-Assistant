from openai import OpenAI
from pydantic import BaseModel
from typing import List
import json


class FirewallAItem(BaseModel): #Creates a new Pydantic model to structure risk assessment data
    rule_set: str
    network_logs: List[str]
    issue: str
    rationale_and_fix: str
    attacks: str
    


class FirewallAIReport(BaseModel): #Creates a new Pydantic model to structure the overall risk report
    items: List[FirewallAItem] 

def openai_risk_filter(openai_client: OpenAI, network_logs, firewall_table_df, promptIn) -> List[FirewallAItem]:
    firewall_table_json = firewall_table_df.to_dict(orient="records")

    system = (
        "You are a senior security engineer reviewing a firewall implementation.\n"
        "Given the firewall specification, test cases, and the firewall rules table, identify bugs, missing edge cases, or redundancies.\n"
        "For each issue, propose a fix and include valid Firewall Table Additions/Changes.\n"
    )

    user = (
        "Firewall specification:\n"
        f"{promptIn}\n\n"
        "Firewall rules table (JSON):\n"
        f"{json.dumps(firewall_table_json, indent=2)}\n\n"
        "Network logs (JSON):\n"
        f"{json.dumps(network_logs, indent=2, default=str)}\n"
    )


    #^ Constructs the user prompt with the payload data formatted as JSON
    resp = openai_client.responses.parse(
         model="gpt-4.1-mini", 
            input=[
                {"role": "system", "content": system}, #Sets the rules/behavior that I want to models data collection/response to abide by
                {"role": "user", "content": user}, #Gives the model the actual request and data you want it to act on
            ],
            text_format=FirewallAIReport
    )
    #^ Sends the request to OpenAI and parses the response into a RiskReport object

    report: FirewallAIReport = resp.output_parsed
    return report.items
