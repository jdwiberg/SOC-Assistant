from pandas import DataFrame
from typing import Any, Dict
from dataclasses import asdict, dataclass
import ipaddress

@dataclass
class FirewallResults():
    network_log: Dict[str, Any]
    action: bool
    rule_set_followed: str


def firewall_rules(df: DataFrame, internal: list[ipaddress.IPv4Address], firewall_df: DataFrame) -> list[dict[str, Any]]:
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
        for idx, row in firewall_df.iterrows():

            #Firewall Direction
            firewall_dir = str(row["Direction"])

            #Firewall Protocol Type
            if(str(row["Protocol"]) == "TCP"):
                firewall_prot = 6
            elif(str(row["Protocol"]) == "UDP"):
                firewall_prot = 17
            else:
                firewall_prot = 0
            
            #Firewall Source Port
            if(row["Source Port"] != -1):
                firewall_src_port = row["Source Port"]
            else:
                firewall_src_port = src_port
            
            #Firewall Destination Port
            if(row["Destination Port"] != -1):
                firewall_dest_port = row["Destination Port"]
            else:
                firewall_dest_port = dst_port

            if(row["ACK Flag"] != -1):
                firewall_ack = row["ACK Flag"]
            else:
                firewall_ack = ack 
            
            # if(row["Source Address"] != "external" or row["Source Address"] != "internal"):

            #and source_address == "external" and dest_address == "internal"
            if(direction == firewall_dir and protocol == firewall_prot and dst_port == firewall_dest_port and src_port == firewall_src_port and ack == firewall_ack):
                results = FirewallResults(network_log=row.to_dict(), 
                                        action=False, 
                                        rule_set_followed = f"{str(row["Firewall Rule"])}")
                data.append(asdict(results))

        # #Rule B
        # elif(direction == "Outgoing" and src_ip == blacklisted_ip and dest_address == "external" and protocol == 6 and dst_port == blacklisted_port):
        #     results = FirewallResults(network_log=row.to_dict(), 
        #                               action=False, 
        #                               rule_set_followed = "Rule B")
        #     data.append(asdict(results))

        # #Rule C
        # elif(direction == "Incoming" and source_address == "external" and dst_ip == blacklisted_ip and protocol == 6 and src_port == blacklisted_port):
        #     results = FirewallResults(network_log=row.to_dict(), 
        #                               action=False, 
        #                               rule_set_followed = "Rule C")
        #     data.append(asdict(results))
        
        # #Rule D
        # elif(direction == "Outgoing" and source_address == "internal" and dest_address == "external" and protocol == 6 and dst_port == blacklisted_port):
        #     results = FirewallResults(network_log=row.to_dict(), 
        #                               action=True, 
        #                               rule_set_followed = "Rule D")
        #     data.append(asdict(results))
        
        # #Rule E
        # elif(direction == "Incoming" and source_address == "external" and dest_address == "internal" and protocol == 6 and src_port == blacklisted_port):
        #     results = FirewallResults(network_log=row.to_dict(), 
        #                               action=True, 
        #                               rule_set_followed = "Rule E")
        #     data.append(asdict(results))
        
        # #Rule F
        # elif(direction == "Incoming" and source_address == "external" and dest_address == "internal" and protocol == blacklisted_protocol):
        #     results = FirewallResults(network_log=row.to_dict(), 
        #                               action=False, 
        #                               rule_set_followed = "Rule F")
        #     data.append(asdict(results))
    
    return data