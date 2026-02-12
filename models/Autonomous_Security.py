from openai import OpenAI
from pydantic import BaseModel
from typing import List, Literal

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

def openai_risk_filter(openai_client: OpenAI, network_logs, promptIn, promptOut) -> list[tuple[str, RiskItem]]:
    
    system = (
        "Given a list of network logs, determine whether each log indicates a network attack and, if so, flag it to be blocked, using attack labels like the following:" 
        f"{promptIn}" 
       # "Look for a possible DDoS Attacks in the given network logs"
    )

    #Misidentifies a lot of Benign calls as DNS Beaconing
    #For each item, output risk (Low/Medium/High), blacklist(true/false), and a 1-sentence rationale.
    user = ( #User prompt for OpenAI
        f"{promptOut}\n"
        f"Data:\n{network_logs}" 
    )
    #^ Constructs the user prompt with the payload data formatted as JSON
    resp = openai_client.responses.parse(
         model="gpt-5-nano", 
            input=[
                {"role": "system", "content": system}, #Sets the rules/behavior that I want to models data collection/response to abide by
                {"role": "user", "content": user}, #Gives the model the actual request and data you want it to act on
            ],
            text_format=RiskReport
    )
    #^ Sends the request to OpenAI and parses the response into a RiskReport object

    report: RiskReport = resp.output_parsed #Pulls the already parsed, validated results out of the OpenAI Response and stores it in report as a RiskReport Object
    #'report.items' is a list of 'RiskItem' objects

    return[
        (item.timestamp, RiskItem(**item.model_dump(exclude={"timestamp"})))
        for item in report.items  #Builds and returns a dictionary that maps each timestamp to its 'RiskItem' object
    ]
