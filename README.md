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

## Scenario: SSH Brute-Force Attack & Detection

### 1. Attack Execution
From the Kali attacker machine, a brute-force attack was launched against the SSH 
service on the target VM using Hydra with a small custom wordlist.

**Command:**
```bash
hydra -l marlinspike -P /tmp/passwords.txt ssh://192.168.10.15 -t 4 -V
```

**Result:** 6 login attempts were made in under 5 seconds. All failed (the correct 
password was deliberately not guessed), simulating a realistic failed brute-force 
attempt.

![Hydra attack output](screenshots/hydra-attack.png)

### 2. Default Detection
Wazuh's built-in rule **5760** ("sshd: authentication failed") correctly fired for 
each failed attempt, confirming basic detection was working as expected.

![Wazuh alert - rule 5760](screenshots/rule-5760-alert.png)

**Sample alert (from alerts.log):**

Rule: 5760 (level 5) -> ‘sshd: authentication failed.’
Src IP: 192.168.10.10
Src Port: 46562
User: marlinspike



### 3. The Gap: Default Correlation Rule Did Not Fire
Wazuh ships with a default correlation rule (**5720**) intended to catch multiple 
authentication failures from the same source. Despite 6 failed attempts in 5 seconds, 
well above what should trigger a brute-force correlation, **this rule never fired**.

Verified directly against the indexer:
```bash
curl -k -u admin:PASSWORD "https://localhost:9200/wazuh-alerts-*/_search?q=rule.id:5720&pretty"
# Result: 0 hits
```

This represents a real detection gap in the default ruleset for fast, low-volume 
brute-force attempts.

### 4. Closing the Gap: Custom Detection Rule

To address the gap left by rule 5720, a custom correlation rule was written and added 
to `/var/ossec/etc/rules/local_rules.xml`:

```xml
<rule id="100002" level="10" frequency="4" timeframe="60">
  <if_matched_sid>5760</if_matched_sid>
  <same_source_ip />
  <description>SSH brute force attempt: multiple authentication failures from the same source IP.</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>authentication_failures,pci_dss_10.2.4,pci_dss_10.2.5,</group>
</rule>
```

**Logic:** if rule 5760 (SSH authentication failure) fires 4 or more times from the 
same source IP within a 60-second window, raise a level 10 alert and tag it to 
**MITRE ATT&CK T1110 (Brute Force)**.

### 5. Verification
After restarting the Wazuh manager and re-running the Hydra attack, rule 100002 fired 
correctly, correlating 4 failed attempts and producing a single high-severity alert:

![Custom rule 100002 firing - part 1](screenshots/rule-100002-alert-1.png)
![Custom rule 100002 firing - part 2](screenshots/rule-100002-alert-2.png)

**Key fields from the alert:**
```json
"rule": {
  "id": "100002",
  "level": 10,
  "frequency": 4,
  "description": "SSH brute force attempt: multiple authentication failures from the same source IP.",
  "mitre": {
    "id": ["T1110"],
    "technique": ["Brute Force"],
    "tactic": ["Credential Access"]
  }
},
"data": {
  "srcip": "192.168.10.10",
  "dstuser": "marlinspike",
  "srcport": "33156"
}
```

This confirms the custom rule correctly identifies brute-force activity that the 
default ruleset missed.
