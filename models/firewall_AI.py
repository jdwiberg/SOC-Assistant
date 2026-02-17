from openai import OpenAI
from pydantic import BaseModel
from typing import List

import json
from pathlib import Path

py_path = Path("Firewall_Rules.py")
json_path = Path("firewall_code.json")

payload = {
    "filename": py_path.name,
    "source": py_path.read_text(encoding="utf-8"),
}

json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
code_text = payload["source"]

class FirewallAItem(BaseModel): #Creates a new Pydantic model to structure risk assessment data
    rule_set: str
    network_logs: List[str]
    issue: str
    rationale_and_fix: str
    attacks: str
    code: str
    


class FirewallAIReport(BaseModel): #Creates a new Pydantic model to structure the overall risk report
    items: List[FirewallAItem] 

def openai_risk_filter(openai_client: OpenAI, network_logs, promptIn) -> List[FirewallAItem]:
    
    system = (
        "You are a senior security engineer reviewing a firewall implementation.\n"
        "Given the firewall specification, large amounts of firewall test cases, and the actual Python code, identify bugs, missing edge cases, or redundancies.\n"
        "For each issue, propose a fix and include valid Python code.\n\n"
        "Firewall specification:\n"
        f"{promptIn}\n\n"
        "Firewall implementation (Python):\n"
        f"{code_text}\n"
    )



    user = (
        "Return ONLY valid JSON matching this schema:\n"
        "{\n"
        '  "items": [\n'
        "    {\n"
        '      "rule_set": "string (Rule A, Rule B, ...)",\n'
        '      "network_logs": ["string", "string", "..."],\n'
        '      "issue": "string (what is wrong in the code vs spec)",\n'
        '      "rationale_and_fix": "string (why it is wrong + what to change)",\n'
        '      "attacks": "string (which attacks slip through OR are misclassified; use dataset labels if present)",\n'
        '      "code": "string (MUST be valid Python; provide a unified diff patch OR a complete corrected function; no placeholders)"\n'
        "    }\n"
        "  ]\n"
        "}\n\n"
        "Hard rules:\n"
        "- Output MUST be valid JSON (no markdown, no extra text).\n"
        "- The 'code' field is REQUIRED for every item (unless items is empty).\n"
        "- 'code' must be executable Python (not pseudocode).\n"
        "- Prefer a unified diff starting with '---' and '+++'; if you can't, output a full corrected function definition.\n"
        "- Use 'network_logs' to reference the specific logs that demonstrate the issue. Use identifiers like id/timestamp/src->dst if available.\n"
        "- Populate 'attacks' with the malicious traffic types that are incorrectly allowed OR incorrectly blocked according to the spec.\n"
        "- If there are no issues, return exactly: {\"items\": []}\n\n"
        f"Network logs:\n{json.dumps(network_logs, indent=2, default=str)}"
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
