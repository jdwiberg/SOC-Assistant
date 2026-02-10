from openai import OpenAI
from pydantic import BaseModel
from typing import List, Dict, Literal

class RiskItem(BaseModel): #Creates a new Pydantic model to structure risk assessment data
    ip_src: str
    # port_src: str
    # ip_dst: str
    port_dest: str
    # protocol: int
    # flow_duration: int
    # tot_fwd_packet: int
    # tot_bwd_packet: int
    risk: Literal["Low", "Medium", "High"] # Risk level
    blacklist: bool # Whether network action was blocked by AI
    rationale: str # Rationale for the risk assessment

class RIwithoutTimeStamp(RiskItem):
    timestamp: str

class RiskReport(BaseModel): #Creates a new Pydantic model to structure the overall risk report
    timestamp: str # Timestamp of the report, "as of" format
    items: List[RIwithoutTimeStamp]  # List of risk items

def openai_risk_filter(openai_client: OpenAI, newtork_logs, promptIn, promptOut) -> Dict[str, RiskItem]:
    
    system = (
        f"{promptIn}"
       # "Look for a possible DDoS Attacks in the given network logs"
    )

    #Misidentifies a lot of Benign calls as DNS Beaconing

    user = ( #User prompt for OpenAI
        #For each item, output risk (Low/Medium/High), blacklist(true/false), and a 1-sentence rationale.
        f"{promptOut}\n\n"
        f"Data:\n{newtork_logs}" 
    )
    #^ Constructs the user prompt with the payload data formatted as JSON
    resp = openai_client.responses.parse(
         model="gpt-4.1-mini", 
            input=[
                {"role": "system", "content": system}, #Sets the rules/behavior that I want to models data collection/response to abide by
                {"role": "user", "content": user}, #Gives the model the actual request and data you want it to act on
            ],
            text_format=RiskReport
    )
    #^ Sends the request to OpenAI and parses the response into a RiskReport object

    report: RiskReport = resp.output_parsed #Pulls the already parsed, validated results out of the OpenAI Response and stores it in report as a RiskReport Object
    #'report.items' is a list of 'RiskItem' objects
    return {item.timestamp: RiskItem(**item.model_dump(exclude="timestamp"))
             for item in report.items}  #Builds and returns a dictionary that maps each timestamp to its 'RiskItem' object

