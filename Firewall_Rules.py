from pandas import DataFrame
from typing import Any
from dataclasses import asdict
import ipaddress


from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class FirewallResults():
    network_log: Dict[str, Any]
    action: bool
    rule_set_followed: str

def firewall_rules(df: DataFrame, internal: list[ipaddress.IPv4Address], blacklisted_ip: ipaddress.IPv4Address, blacklisted_port: int, blacklisted_protocol: int) -> list[dict[str, Any]]:
    data: list[dict[str, Any]] = []
    for idx, row in df.iterrows():
        src_ip = ipaddress.IPv4Address(int(str(row["Src IP dec"]).replace(",", "")))
        src_port = int(str(row["Src Port"]).replace(",", ""))
        dst_ip = ipaddress.IPv4Address(int(str(row["Dst IP dec"]).replace(",", "")))
        dst_port = int(str(row["Dst Port"]).replace(",", ""))
        protocol = int(str(row["Protocol"]).replace(",", ""))
        ack = int(str(row["ACK Flag Count"]).replace(",", ""))

        direction = "Incoming"
        source_address = "external"
        dest_address = "internal"
        if (src_ip) in internal:
            direction = "Outgoing"
            source_address = "internal"
            dest_address = "external"
    
        #Rule A
        if(direction == "Incoming" and source_address == "external" and dest_address == "internal" and protocol == 6 and dst_port == blacklisted_port and ack == 0):
            results = FirewallResults(network_log=row.to_dict(), 
                                      action=False, 
                                      rule_set_followed = "Rule A")
            data.append(asdict(results))

        #Rule B
        elif(direction == "Outgoing" and src_ip == blacklisted_ip and dest_address == "external" and protocol == 6 and dst_port == blacklisted_port):
            results = FirewallResults(network_log=row.to_dict(), 
                                      action=False, 
                                      rule_set_followed = "Rule B")
            data.append(asdict(results))

        #Rule C
        elif(direction == "Incoming" and source_address == "external" and dst_ip == blacklisted_ip and protocol == 6 and src_port == blacklisted_port):
            results = FirewallResults(network_log=row.to_dict(), 
                                      action=False, 
                                      rule_set_followed = "Rule C")
            data.append(asdict(results))
        
        #Rule D
        elif(direction == "Outgoing" and source_address == "internal" and dest_address == "external" and protocol == 6 and dst_port == blacklisted_port):
            results = FirewallResults(network_log=row.to_dict(), 
                                      action=True, 
                                      rule_set_followed = "Rule D")
            data.append(asdict(results))
        
        #Rule E
        elif(direction == "Incoming" and source_address == "external" and dest_address == "internal" and protocol == 6 and src_port == blacklisted_port):
            results = FirewallResults(network_log=row.to_dict(), 
                                      action=True, 
                                      rule_set_followed = "Rule E")
            data.append(asdict(results))
        
        #Rule F
        elif(direction == "Incoming" and source_address == "external" and dest_address == "internal" and protocol == blacklisted_protocol):
            results = FirewallResults(network_log=row.to_dict(), 
                                      action=False, 
                                      rule_set_followed = "Rule F")
            data.append(asdict(results))
    
    return data