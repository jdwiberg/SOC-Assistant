from openai import OpenAI
from typing import Literal
from dataclasses import dataclass
import json
import re

@dataclass
class RiskReport: #Creates a new Pydantic model to structure risk assessment data
    attack_type: Literal["BENIGN", "DoS", "PortScan", "BruteForce"]
    risk: Literal["Low", "Medium", "High"] # Risk level
    blacklist: bool # Whether network action was blocked by AI
    rationale: str # Rationale for the risk assessment


def _extract_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(json)?\s*|\s*```$", "", text, flags=re.IGNORECASE).strip()
    if text.startswith("{") and text.endswith("}"):
        return json.loads(text)
    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if match:
        return json.loads(match.group(0))
    raise ValueError(f"Could not find JSON object in LLM output: {text[:200]}...")


def openai_risk_filter(openai_client: OpenAI, network_logs, promptIn) -> RiskReport:
    
    system = f"{promptIn}" 
    user = f"Here is the network flow data:\n{network_logs}"
    #^ Constructs the user prompt with the payload data formatted as JSON
    resp = openai_client.responses.create(
         model="gpt-5-nano", 
            input=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ]
    )
    # print(type(resp))
    # print(resp)
    #^ Sends the request to OpenAI and parses the response into a RiskReport object
    text_output = getattr(resp, "output_text", None)
    if not text_output:
        text_output = resp.output[0].content[0].text
    data = _extract_json(text_output)
    report = RiskReport(**data)

    return report
