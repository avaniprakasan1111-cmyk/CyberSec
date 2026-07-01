# Networking Fundamentals for SOC

## SOC Analyst Study Notes

### Goal

Understand basic networking concepts from a SOC analyst perspective, including how network activity appears in logs, how to identify normal vs suspicious traffic, and how to investigate scanning or unusual connections.

---

## Topics Covered

- OSI model: Layer 3, Layer 4, Layer 7
- TCP/IP model
- IPv4, IPv6, subnetting, and CIDR
- Public IP vs private IP
- TCP vs UDP
- TCP flags: SYN, ACK, RST, FIN
- Common ports: 21, 22, 25, 53, 80, 443, 445, 3389
- SYN scan, connect scan, UDP scan
- Source IP, destination IP, source port, destination port
- Normal vs suspicious traffic
- Subnetting practice: /24, /25, /26, /27
- Microsoft Sentinel KQL examples

---

## Table of Contents

1. [OSI Model for SOC](#1-osi-model-for-soc)
2. [TCP/IP Model](#2-tcpip-model)
3. [IPv4 and IPv6](#3-ipv4-and-ipv6)
4. [Public IP vs Private IP](#4-public-ip-vs-private-ip)
5. [Subnetting and CIDR](#5-subnetting-and-cidr)
6. [TCP vs UDP](#6-tcp-vs-udp)
7. [TCP Flags](#7-tcp-flags-syn-ack-rst-fin)
8. [Common Ports for SOC](#8-common-ports-for-soc)
9. [Source and Destination Fields](#9-source-ip-destination-ip-source-port-and-destination-port)
10. [Normal vs Suspicious Traffic](#10-normal-vs-suspicious-traffic)
11. [Port Scanning](#11-port-scanning)
12. [SOC Investigation Example](#12-soc-example-investigation)
13. [KQL Examples](#13-simple-kql-examples-for-microsoft-sentinel)
14. [Practice Questions](#14-practice-questions)
15. [Final SOC Key Takeaways](#final-soc-key-takeaways)

---

# 1. OSI Model for SOC

The OSI model explains how communication happens between systems. For SOC work, the most important layers are **Layer 3, Layer 4, and Layer 7** because most security logs contain IP addresses, ports, protocols, and application details.

| OSI Layer | Name | SOC Meaning | Example |
|---|---|---|---|
| Layer 3 | Network Layer | IP addresses, routing, source IP, destination IP | `192.168.1.10 -> 8.8.8.8` |
| Layer 4 | Transport Layer | Ports and protocols such as TCP/UDP | TCP 443, UDP 53 |
| Layer 7 | Application Layer | Application or service being used | HTTP, DNS, SMTP, RDP |

---

## Layer 3 - Network Layer

Layer 3 deals with IP addressing and routing. In SOC alerts, this layer helps identify:

- Who started the connection
- Who received the connection
- Whether the traffic is internal or external
- Whether the IP address is suspicious

| SOC Question | Example |
|---|---|
| Who started the connection? | Source IP |
| Who received the connection? | Destination IP |
| Is it internal or external? | Private IP vs public IP |
| Is the IP known malicious? | Threat intelligence check |
| Is the country or ASN unusual? | GeoIP / ASN lookup |

Example:

```text
Source IP: 10.0.5.23
Destination IP: 185.199.110.153
```

SOC question:

```text
Is this internal host communicating with a legitimate external service or a suspicious public IP?
```

---

## Layer 4 - Transport Layer

Layer 4 deals with TCP, UDP, and ports. This layer helps identify what service was accessed and whether the connection pattern looks normal or suspicious.

| SOC Question | Example |
|---|---|
| What protocol was used? | TCP or UDP |
| What port was used? | 443, 3389, 445 |
| Was it a connection attempt? | SYN packet |
| Was it reset or blocked? | RST packet |
| Was there scanning? | Many SYN packets to many ports or many IPs |

Example:

```text
Source IP: 10.0.1.25
Destination IP: 10.0.1.50
Protocol: TCP
Destination Port: 445
```

SOC meaning:

```text
Port 445 is SMB. It may be normal file sharing, but it can also indicate lateral movement or ransomware activity.
```

---

## Layer 7 - Application Layer

Layer 7 shows the actual application protocol, domain, URL, user-agent, command, or application behavior.

| Protocol | Purpose | SOC Example |
|---|---|---|
| HTTP | Web browsing | Suspicious file download over HTTP |
| HTTPS | Encrypted web traffic | Beaconing to an unknown domain every 60 seconds |
| DNS | Domain lookup | Random-looking domains or very high query volume |
| SMTP | Email transfer | Workstation sending mail directly to the internet |
| SMB | Windows file sharing | One host connecting to many internal systems |
| RDP | Remote desktop | External brute-force or unusual admin login |

---

# 2. TCP/IP Model

The TCP/IP model is the practical model used in real networks. It has fewer layers than OSI but maps closely to the same SOC log fields.

| TCP/IP Layer | Related OSI Layers | Examples |
|---|---|---|
| Application | OSI Layer 5-7 | HTTP, DNS, SMTP |
| Transport | OSI Layer 4 | TCP, UDP |
| Internet | OSI Layer 3 | IP, ICMP |
| Network Access | OSI Layer 1-2 | Ethernet, Wi-Fi, MAC |

Example log:

```text
Time: 10:32:15
Source IP: 192.168.1.20
Destination IP: 8.8.8.8
Protocol: UDP
Destination Port: 53
Action: Allowed
```

Meaning:

```text
An internal machine made a DNS request to Google DNS.
```

SOC note:

```text
One DNS request is usually normal. Thousands of DNS requests to random domains from the same host may indicate malware, DNS tunneling, or command-and-control activity.
```

---

# 3. IPv4 and IPv6

## IPv4

IPv4 is the most common IP address format. It has four numbers separated by dots. Each number can range from 0 to 255.

Examples:

```text
192.168.1.10
8.8.8.8
172.16.5.20
```

| Field | Meaning |
|---|---|
| Source IP | System that started the connection |
| Destination IP | System or server being contacted |
| Internal IP | Device inside your organization network |
| External IP | Internet-facing system |
| Malicious IP | Known attacker, malware C2, scanner, or suspicious hosting IP |

---

## IPv6

IPv6 is a newer IP addressing system. It was created because IPv4 addresses are limited. IPv6 addresses are longer and separated by colons.

Full IPv6:

```text
2001:0db8:85a3:0000:0000:8a2e:0370:7334
```

Shortened IPv6:

```text
2001:db8:85a3::8a2e:370:7334
```

| SOC Use | Explanation |
|---|---|
| Check if IPv6 is enabled | Attackers may use IPv6 if monitoring is weak |
| Detect unusual IPv6 traffic | Some networks monitor IPv4 well but forget IPv6 |
| Identify internal/external IPv6 | Same investigation logic as IPv4 |
| Investigate tunneling | IPv6 can sometimes be abused to bypass controls |

Suspicious example:

```text
A host that normally uses IPv4 suddenly starts making IPv6 outbound connections.
This is not automatically malicious, but it should be checked.
```

---

# 4. Public IP vs Private IP

## Private IP

Private IP addresses are used inside internal networks. They are not directly reachable from the public internet.

| Private Range | Example |
|---|---|
| 10.0.0.0/8 | 10.10.5.20 |
| 172.16.0.0/12 | 172.16.8.50 |
| 192.168.0.0/16 | 192.168.1.100 |

---

## Public IP

Public IP addresses are internet-routable. They belong to external services, cloud providers, ISPs, hosting providers, VPNs, or malicious infrastructure.

Examples:

```text
8.8.8.8
1.1.1.1
185.199.110.153
```

| SOC Check | Why It Matters |
|---|---|
| Reputation | Is the IP known malicious? |
| Geo-location | Is the country unusual for this user or system? |
| ASN / owner | Is it cloud, ISP, hosting, VPN, proxy, or Tor? |
| Frequency | Is there repeated communication or beaconing? |
| Direction | Is it inbound or outbound? |

Suspicious example:

```text
Internal host 10.0.1.25 connects to unknown public IP 45.90.x.x on port 4444.
```

Possible meaning:

```text
Command-and-control communication.
```

---

# 5. Subnetting and CIDR

Subnetting divides a larger network into smaller networks. CIDR notation shows how many bits are used for the network portion.

Example:

```text
192.168.1.0/24
```

| SOC Use | Example |
|---|---|
| Identify network range | Is this IP in our office subnet? |
| Scope an incident | Which devices are in the affected subnet? |
| Detect scanning | One host contacting all IPs in a subnet |
| Firewall rules | Allow or block a subnet |
| Asset grouping | Servers, users, printers, DMZ |

---

## Easy Subnet Memory Table

| CIDR | Subnet Mask | Total IPs | Usable Hosts | Block Size |
|---|---|---:|---:|---:|
| /24 | 255.255.255.0 | 256 | 254 | 256 |
| /25 | 255.255.255.128 | 128 | 126 | 128 |
| /26 | 255.255.255.192 | 64 | 62 | 64 |
| /27 | 255.255.255.224 | 32 | 30 | 32 |

---

## /24 Subnet

```text
Network: 192.168.1.0/24
Subnet mask: 255.255.255.0
Total IPs: 256
Usable hosts: 254
Network address: 192.168.1.0
First usable: 192.168.1.1
Last usable: 192.168.1.254
Broadcast: 192.168.1.255
```

SOC use:

```text
If one attacker scans 192.168.1.1 to 192.168.1.254, they are scanning the full /24 subnet.
```

---

## /25 Subnet

A `/25` splits a `/24` into 2 subnets. Each subnet has 128 total IPs and 126 usable hosts.

| Subnet | Usable Range | Broadcast |
|---|---|---|
| 192.168.1.0/25 | 192.168.1.1 - 192.168.1.126 | 192.168.1.127 |
| 192.168.1.128/25 | 192.168.1.129 - 192.168.1.254 | 192.168.1.255 |

Example:

```text
192.168.1.50 belongs to 192.168.1.0/25
192.168.1.200 belongs to 192.168.1.128/25
```

---

## /26 Subnet

A `/26` splits a `/24` into 4 subnets. Each subnet has 64 total IPs and 62 usable hosts.

| Subnet | Usable Range | Broadcast |
|---|---|---|
| 192.168.1.0/26 | 192.168.1.1 - 192.168.1.62 | 192.168.1.63 |
| 192.168.1.64/26 | 192.168.1.65 - 192.168.1.126 | 192.168.1.127 |
| 192.168.1.128/26 | 192.168.1.129 - 192.168.1.190 | 192.168.1.191 |
| 192.168.1.192/26 | 192.168.1.193 - 192.168.1.254 | 192.168.1.255 |

Example:

```text
192.168.1.70 belongs to 192.168.1.64/26
```

---

## /27 Subnet

A `/27` splits a `/24` into 8 subnets. Each subnet has 32 total IPs and 30 usable hosts.

| Subnet | Usable Range | Broadcast |
|---|---|---|
| 192.168.1.0/27 | 192.168.1.1 - 192.168.1.30 | 192.168.1.31 |
| 192.168.1.32/27 | 192.168.1.33 - 192.168.1.62 | 192.168.1.63 |
| 192.168.1.64/27 | 192.168.1.65 - 192.168.1.94 | 192.168.1.95 |
| 192.168.1.96/27 | 192.168.1.97 - 192.168.1.126 | 192.168.1.127 |
| 192.168.1.128/27 | 192.168.1.129 - 192.168.1.158 | 192.168.1.159 |
| 192.168.1.160/27 | 192.168.1.161 - 192.168.1.190 | 192.168.1.191 |
| 192.168.1.192/27 | 192.168.1.193 - 192.168.1.222 | 192.168.1.223 |
| 192.168.1.224/27 | 192.168.1.225 - 192.168.1.254 | 192.168.1.255 |

Example:

```text
192.168.1.100 belongs to 192.168.1.96/27
```

---

# 6. TCP vs UDP

## TCP

TCP is connection-oriented. It establishes a connection, confirms delivery, and is used when reliability matters.

| Protocol | Port | Typical Use |
|---|---:|---|
| HTTP | 80 | Web browsing |
| HTTPS | 443 | Secure web traffic |
| SSH | 22 | Secure administration |
| SMTP | 25 | Email transfer |
| SMB | 445 | Windows file sharing |
| RDP | 3389 | Remote desktop |

TCP three-way handshake:

```text
Client -> Server: SYN
Server -> Client: SYN-ACK
Client -> Server: ACK
```

| Suspicious TCP Activity | Possible Meaning |
|---|---|
| Many SYN packets to many ports | Port scanning |
| Many failed connections | Reconnaissance |
| RDP from external IP | Brute force or unauthorized access |
| SMB between many internal hosts | Worm, ransomware, or lateral movement |
| Repeated RST packets | Blocked or failed connections |

---

## UDP

UDP is connectionless. It does not create a session like TCP. It is often used where speed is more important than reliability.

| Protocol | Port | Typical Use |
|---|---:|---|
| DNS | 53 | Domain name lookup |
| DHCP | 67/68 | IP address assignment |
| NTP | 123 | Time synchronization |
| SNMP | 161 | Network device monitoring |
| VoIP/SIP | 5060 | Voice signaling |

SOC note:

```text
UDP does not have SYN, ACK, or FIN flags.
Detection is based on volume, destination ports, destination count, failed responses, and unusual patterns.
```

| Suspicious UDP Activity | Possible Meaning |
|---|---|
| High-volume UDP traffic | DDoS, scanning, or tunneling |
| Many DNS queries | Malware, DNS tunneling, or C2 |
| UDP to unusual ports | Suspicious tool or malware |
| External UDP from internal host | Possible command-and-control |

---

# 7. TCP Flags: SYN, ACK, RST, FIN

TCP flags show the state of a TCP connection. They are useful when investigating scanning and failed connection attempts.

| Flag | Meaning | SOC Interpretation |
|---|---|---|
| SYN | Start a TCP connection | Many SYN packets to many ports or IPs can indicate scanning |
| ACK | Acknowledgement | Common in normal traffic; unusual ACK scans may test firewall rules |
| RST | Reset connection | Many RST responses may indicate closed ports or blocked scan attempts |
| FIN | Finish connection | Normal close; FIN scans may be used for stealthy reconnaissance |

Example SYN activity:

```text
10.0.1.5 -> 10.0.1.20 TCP 445 SYN
```

Meaning:

```text
10.0.1.5 is trying to connect to SMB on 10.0.1.20.
```

---

# 8. Common Ports for SOC

| Port | Service | Protocol | Purpose | SOC Concern |
|---:|---|---|---|---|
| 21 | FTP | TCP | File transfer | Clear-text credentials/data; unknown external FTP upload may indicate data exfiltration |
| 22 | SSH | TCP | Secure remote administration | Repeated failed SSH logins may indicate brute force |
| 25 | SMTP | TCP | Email transfer | Workstation sending SMTP directly to internet may indicate spam malware |
| 53 | DNS | UDP/TCP | Domain name resolution | High query volume, random domains, unusual TLDs, or long domains may indicate DNS tunneling or malware |
| 80 | HTTP | TCP | Unencrypted web traffic | Executable downloads or suspicious URLs may indicate malware delivery |
| 443 | HTTPS | TCP | Encrypted web traffic | Check domain, certificate, reputation, frequency, and data volume |
| 445 | SMB | TCP | Windows file sharing | One workstation connecting to many internal hosts may indicate lateral movement or ransomware |
| 3389 | RDP | TCP | Remote desktop | External or unusual RDP access may indicate brute force or unauthorized remote access |

Important notes:

- Port 443 does not automatically mean safe. Malware can also communicate over HTTPS.
- Port 445 is important in internal investigations because it is often abused for lateral movement.
- Port 3389 exposed to the internet is high risk and should be investigated carefully.
- Port 53 should be monitored for high volume, random-looking domains, repeated failed lookups, and tunneling behavior.

---

# 9. Source IP, Destination IP, Source Port, and Destination Port

These are core fields in almost every network security investigation.

Example log:

```text
Time: 2026-05-12 10:15:22
Source IP: 10.0.1.25
Source Port: 51544
Destination IP: 8.8.8.8
Destination Port: 53
Protocol: UDP
Action: Allowed
```

Meaning:

```text
10.0.1.25 used temporary source port 51544 to contact DNS server 8.8.8.8 on UDP port 53.
```

| Field | Meaning |
|---|---|
| Source IP | Device that started the connection |
| Source Port | Temporary client-side port, usually high-numbered |
| Destination IP | Device, server, or public service being contacted |
| Destination Port | Service being accessed, such as 443 for HTTPS or 3389 for RDP |
| Protocol | TCP, UDP, ICMP, etc. |
| Action | Allowed, blocked, denied, reset, dropped |

SOC shortcut:

```text
Destination port usually tells you the service.
Source port is often a temporary high-numbered client port.
```

---

# 10. Normal vs Suspicious Traffic

## Normal Traffic Examples

| Traffic | Why It Can Be Normal |
|---|---|
| Internal host to DNS server on UDP 53 | Normal DNS lookup |
| User laptop to website on TCP 443 | Normal web browsing or SaaS usage |
| Admin workstation to server on TCP 22 | Normal SSH administration |
| User to file server on TCP 445 | Normal file share access |
| Mail server to external mail server on TCP 25 | Normal email transfer |

---

## Suspicious Traffic Examples

| Traffic | Why Suspicious |
|---|---|
| Workstation sending SMTP directly to internet | Possible spam malware |
| One host connecting to many IPs on port 445 | Possible lateral movement, worm, or ransomware |
| External IP trying many RDP logins | Brute-force attack |
| Many failed connections to many ports | Port scanning |
| DNS queries to random domains | DNS tunneling or malware |
| HTTPS beacon every 30 seconds | Command-and-control communication |
| Internal host contacting known malicious IP | Compromise indicator |
| Large upload to unknown external IP | Possible data exfiltration |

---

## SOC Investigation Questions

When investigating suspicious network traffic, ask:

- Who is the source?
- Who is the destination?
- Is the destination internal or external?
- What port and protocol are being used?
- Is this port expected for this system?
- Was the action allowed, blocked, denied, or reset?
- Is the time normal for the user or system?
- Is the volume normal?
- Is the destination known malicious?
- Has this happened before?
- Are there related login, endpoint, DNS, proxy, or EDR alerts?

---

# 11. Port Scanning

Port scanning is used to find open services on a system or across a network. Attackers scan to discover live hosts, open ports, services, and possible vulnerabilities.

| Scanning Indicator | SOC Meaning |
|---|---|
| Many connection attempts | Possible reconnaissance |
| Many destination ports | Port scan against one host |
| Many destination IPs | Network sweep |
| Short time window | Automated scanning tool |
| Repeated SYN packets | Possible SYN scan |
| Many denied firewall logs | Blocked scanning attempt |

---

## SYN Scan

A SYN scan is also called a half-open scan. The attacker sends SYN packets and observes the response without completing a full connection.

```text
Attacker -> Target: SYN
Target -> Attacker: SYN-ACK means port may be open
Target -> Attacker: RST means port may be closed
```

Example SYN scan pattern:

```text
10.0.1.50 -> 10.0.1.10:22 SYN
10.0.1.50 -> 10.0.1.10:80 SYN
10.0.1.50 -> 10.0.1.10:443 SYN
10.0.1.50 -> 10.0.1.10:445 SYN
10.0.1.50 -> 10.0.1.10:3389 SYN
```

Conclusion:

```text
10.0.1.50 may be scanning 10.0.1.10.
```

---

## Connect Scan

A connect scan completes the full TCP handshake. It is easier to log because the connection is fully established.

Connect scan handshake:

```text
SYN -> SYN-ACK -> ACK
```

| SYN Scan | Connect Scan |
|---|---|
| Half-open connection | Full connection |
| More stealthy | Easier to log |
| Does not complete handshake | Completes handshake |
| Often seen as many SYN packets | Seen as many successful short connections |

---

## UDP Scan

A UDP scan checks for open UDP services. It is harder to detect because UDP does not use SYN or ACK.

| Common UDP Port | Service |
|---:|---|
| 53 | DNS |
| 67/68 | DHCP |
| 123 | NTP |
| 161 | SNMP |
| 500 | IKE VPN |
| 514 | Syslog |

| UDP Scan Indicator | Possible Meaning |
|---|---|
| Many UDP packets to many ports | UDP reconnaissance |
| Many ICMP port unreachable responses | Closed UDP ports being probed |
| Unusual UDP traffic volume | Scanning, tunneling, or abuse |
| UDP packets to port 161 across many systems | Possible SNMP scanning |

---

# 12. SOC Example Investigation

## Alert

```text
Potential Port Scan Detected

Source IP: 10.0.1.45
Destination Range: 10.0.1.0/24
Protocol: TCP
Ports: 21, 22, 80, 443, 445, 3389
Time Window: 5 minutes
```

---

## L1 SOC Analysis

The SOC analyst should check:

- Is `10.0.1.45` a known vulnerability scanner or admin server?
- Is this scan scheduled or approved by a change ticket?
- Is the source a user workstation or a server?
- Were connections allowed, blocked, reset, or denied?
- Which destination IPs and ports were contacted?
- Are there related EDR, login, DNS, proxy, or firewall alerts?

---

## Suspicious Indicators

- Source is not a known scanner.
- Source is a normal user workstation, not an admin or security system.
- Many ports were checked quickly.
- Multiple internal systems were contacted.
- High-risk ports 445 and 3389 were included.
- No approved change ticket or maintenance window exists.

---

## Possible Verdict

```text
Suspicious internal reconnaissance activity.
Escalate to L2 with evidence and request containment decision if confirmed.
```

---

## Escalation Details to Include

- Source IP and hostname
- Logged-in user
- Destination IPs
- Ports scanned
- Time window
- Firewall, network, and EDR evidence
- Whether traffic was allowed or blocked
- Any related alerts or previous activity

---

# 13. Simple KQL Examples for Microsoft Sentinel

## Find traffic to RDP

```kql
CommonSecurityLog
| where DestinationPort == 3389
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort, Protocol, DeviceAction
```

---

## Find possible port scanning against one destination

```kql
CommonSecurityLog
| summarize PortCount=dcount(DestinationPort), Ports=make_set(DestinationPort)
    by SourceIP, DestinationIP, bin(TimeGenerated, 5m)
| where PortCount > 10
| order by PortCount desc
```

---

## Find one host connecting to many internal IPs

```kql
CommonSecurityLog
| summarize DestinationCount=dcount(DestinationIP), Destinations=make_set(DestinationIP, 20)
    by SourceIP, DestinationPort, bin(TimeGenerated, 5m)
| where DestinationCount > 20
| order by DestinationCount desc
```

---

## Find DNS traffic

```kql
CommonSecurityLog
| where DestinationPort == 53
| project TimeGenerated, SourceIP, DestinationIP, Protocol, DeviceAction
```

---

## Find high DNS volume by source

```kql
CommonSecurityLog
| where DestinationPort == 53 or Protocol =~ "DNS"
| summarize TotalDNSQueries=count(), UniqueDestinations=dcount(DestinationIP)
    by SourceIP, bin(TimeGenerated, 1h)
| where TotalDNSQueries > 1000
| order by TotalDNSQueries desc
```

---

# 14. Practice Questions

## Question 1

```text
Source IP 10.0.1.20 to destination IP 8.8.8.8 on UDP 53.
What is this?
```

Answer:

```text
DNS traffic from an internal host to Google DNS.
Usually normal, but check volume, destination policy, and queried domains.
```

---

## Question 2

```text
Source IP 10.0.1.55 contacts 10.0.1.1-10.0.1.254 on destination port 445.
What is suspicious?
```

Answer:

```text
One internal host is contacting many systems on SMB.
This may indicate lateral movement, worm activity, or ransomware spreading.
```

---

## Question 3

```text
192.168.1.75 belongs to which /26 subnet?
```

Answer:

```text
192.168.1.64/26
Usable range: 192.168.1.65 - 192.168.1.126
Broadcast: 192.168.1.127
```

---

## Question 4

```text
Destination port 3389 means what service?
```

Answer:

```text
RDP - Remote Desktop Protocol.
External or unusual RDP access can indicate brute force or unauthorized remote access.
```

---

## Question 5

```text
Many SYN packets from one host to many ports can indicate what?
```

Answer:

```text
Possible SYN scan or port scanning activity.
```

---

## Question 6

```text
A workstation sends email directly to the internet using TCP 25.
Why is this suspicious?
```

Answer:

```text
Normal users usually send mail through approved mail services.
Direct SMTP from a workstation may indicate spam malware or compromise.
```

---

## Question 7

```text
A host sends HTTPS traffic to the same unknown IP every 60 seconds.
What could this indicate?
```

Answer:

```text
Possible command-and-control beaconing.
Check reputation, domain, certificate, user-agent, and endpoint process.
```

---

## Question 8

```text
A host sends many UDP packets to port 161 across many devices.
What could this indicate?
```

Answer:

```text
Possible SNMP scanning or reconnaissance.
```

---

# Final SOC Key Takeaways

- Layer 3 = IP addresses and routing.
- Layer 4 = TCP/UDP and ports.
- Layer 7 = application protocols such as HTTP, DNS, SMTP, SMB, and RDP.
- TCP is reliable and connection-based.
- UDP is connectionless and faster.
- SYN starts a connection.
- ACK acknowledges.
- RST resets or refuses.
- FIN closes a connection.
- Destination port usually identifies the service being accessed.
- Port 445 and port 3389 are high-risk in SOC investigations.
- Many ports or many destinations in a short time can indicate scanning.
- Subnetting helps define the scope of affected systems.
- Always combine network logs with endpoint, identity, DNS, proxy, and threat intelligence evidence.

---

## Author

**Your Name**  
SOC Analyst Learning Journey  
GitHub Portfolio Project
