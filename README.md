SOC log analysis using Splunk and Windows Event Logs
# Windows Event Log Analysis with Splunk

## Objective
This project focuses on analyzing Windows Security Event Logs using Splunk to identify potential reconnaissance activities, specifically local group enumeration.

## Tools Used
* **Splunk Enterprise** (SIEM)
* **Windows 10/11** (Target Machine)
* **PowerShell** (For event generation)

## Technical Analysis: Event Code 4798
The screenshot below captures **Event Code 4798**, which triggers when a user's local group membership is enumerated. In a real-world scenario, attackers use this to find accounts with administrative privileges.

<img width="1118" height="600" alt="all-logs" src="https://github.com/user-attachments/assets/3fb089cf-3cdf-4174-b1e8-1f5e0b76faa4" />

### Splunk Search Query
To find these specific events, I used the following SPL:
`index="main" EventCode=4798 | table _time, ComputerName, Subject_Account_Name, Message`

## Key Observations
* **Account Name:** [Redacted] performed the enumeration.
* **Process Name:** `C:\Windows\explorer.exe`
* **Significance:** Frequent 4798 events from an unusual user account can indicate a "Discovery" phase of the MITRE ATT&CK framework.


-------------------------------------------------------------------------------------
## Technical Analysis: Event Code 4625 (Logon Failure)<img width="1795" height="1071" alt="failed-login" src="https://github.com/user-attachments/assets/b173bb8d-d408-4d62-9508-79b2eca67d4c" />
### Incident Overview
This event represents a **Failed Logon attempt**. Analyzing these is crucial for identifying brute-force attacks.

* **Target Account:** ****
* **Failure Reason:** 0xC000006E (Account is disabled)
* **Logon Type:** 3 (Network Logon)

### Security Significance
A **Logon Type 3** indicates the attempt happened over the network. Seeing this against a **Guest** account (which is disabled by default) is a strong indicator of automated scanning or "noise" from a bot trying to find open shares on the network.



---------------------------------------------------------------------------------------
---

## Technical Analysis: Event Code 4624 (Successful Service Logon)
While monitoring for failures is important, baseline monitoring of successful logons is key to detecting lateral movement or persistence.

### Evidence
<img width="1522" height="982" alt="Successful-login" src="https://github.com/user-attachments/assets/5e061bea-e954-43b6-abc0-fc24f1956016" />


### Analysis & Interpretation
* **Event ID:** 4624 (An account was successfully logged on)
* **Logon Type 5 (Service):** This indicates that a service was started by the Service Control Manager. It is not an interactive session (human user).
* **Source Process:** `services.exe`
* **Security Insight:** In this log, we see an elevated token being used. In a SOC environment, we monitor Type 5 logons to ensure that only authorized services are running with System/Admin privileges. Sudden new Type 5 logons can sometimes indicate a malicious service being installed for persistence.

### Splunk Search Query
```sql
index="main" EventCode=4624 Logon_Type=5 
| stats count by ComputerName, Account_Name, Process_Name


--------------------------------------------------
By including three different event types (4798, 4625, and 4624), you are effectively showing the **full lifecycle of a security event**:
1.  **Reconnaissance** (4798)
2.  **Failed Access Attempt** (4625)
3.  **Successful System Activity** (4624)
