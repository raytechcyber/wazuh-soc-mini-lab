# SSH Brute-Force Detection with Wazuh — Mini SOC Lab

## Overview
This project simulates and detects an SSH brute-force attack in a small home SOC lab 
built with Wazuh (SIEM/XDR). It demonstrates the full detection lifecycle: running an 
attack, verifying default detection rules, identifying a gap in Wazuh's default 
correlation logic, and writing a custom detection rule to close that gap — mapped to 
the MITRE ATT&CK framework.

**Key finding:** Wazuh's default correlation rule for repeated SSH failures (rule 5720) 
did not trigger during a fast brute-force burst (6 attempts in 5 seconds). A custom 
rule was written and verified to correctly detect this pattern.

## Lab Environment
- **Attacker:** Kali Linux (also hosting the Wazuh Manager, Indexer, and Dashboard)
- **Target:** Ubuntu-based VM ("vtcsec"), monitored via Wazuh agent
- **Network:** VirtualBox internal network (192.168.10.0/24)
- **Tools:** Wazuh 4.14.7, Hydra, OpenSearch/Wazuh Dashboard
