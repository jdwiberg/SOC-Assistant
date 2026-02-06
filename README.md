# SOC-Assistant
A weak SOC-assistant, the strategy for breaking it, and a stronger and more durable update.

## Steps:
1. Create/obtain small 'log dataset'
   * between 50 and 200 JSON log lines (auth logs, DNS logs, firewall logs)
   * or generate synthetic incidents (brute force, port scan, malware beacon, data exfil)
   * or both
2. Create Small Retrieval layer
   * user selects a time window
   * fetch all logs during this time
   * optional: add a mini "knowledge base" doc to teach llm how to interpret logs, reason about behavior, what is normal vs sus, and what actions are inappropriate
   * the knowledge base is the mental model for how to solve these problems (generating incident reports)
3. LLM prompt that outputs a structured incident report
   * give LLM what happened, define a strucutre for what to return, parse
5. Figure out how to break LLM
6. Figure out how to make LLM stronger

## Concepts to Know
* IP/Subnet Basics (internal vs external IPs)
* TCP vs UDP
* Ports + common services (80/443 web, 22 ssh, 53 dns, 3389 rdp, 445 smb)
* DNS basics (queries, domains, why it matters)
* HTTP basics (requests, user agents)
* Firewall flow logs (Firewall flow logs (src/dst IP, src/dst port, bytes, action allow/deny)

## 3 Prototype Incidents to Use
1. Brute force -> successful login
   * Many failed logins from the same IP
   * LLM: “possible credential stuffing/brute force, investigate account and source IP”
2. Port Scan
  * One src IP hits many ports or many hosts quickly
  * LLM: "recon activity, check if its internal vulnerability scanner or attacker"
3. Suspicious DNS + beaconing
  * Repeated DNS queries to random-looking domains
  * Regular outbound connections every X minutes
  * LLM: "possible C2 beaconing, identify processs/host, block domain, isolate host"

## Possible Product Flow
* 00:00 - 23:59
* All day, logs come in
* The user can select a time frame and a model (strong or weak) to invesitage all the logs during that time
* At some point there might be different attacks, and at some point there will be an LLM attack
* The website should either output how many attacks were identified out of the total, or give the user instructions to see how many can be identified by the user
