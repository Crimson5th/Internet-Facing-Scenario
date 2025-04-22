# Internet-Facing-Scenario

Devices Accidentally Exposed to the Internet Scenario:

1. Preparation
● Goal: Set up the hunt by defining what you're looking for.
○ During routine maintenance, the security team is tasked with investigating any VMs in the
shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly
been exposed to the public internet. The goal is to identify any misconfigured VMs and check for
potential brute-force login attempts/successes from external sources.

● Activity: Develop a hypothesis based on threat intelligence and security gaps (e.g., “Could there be
lateral movement in the network?”).
○ During the time the devices were unknowingly exposed to the internet, it’s possible that
someone could have actually brute-force logged into some of them since some of the older
devices do not have account lockout configured for excessive failed login attempts.


2. Data Collection
● Goal: Gather relevant data from logs, network traffic, and endpoints.
● Activity: Ensure data is available from all key sources for analysis.


3. Data Analysis
● Goal: Analyze data to test your hypothesis.
● Activity: Look for anomalies, patterns, or indicators of compromise (IOCs) using various tools and
techniques.


4. Investigation
● Goal: Investigate any suspicious findings.
● Activity: Dig deeper into detected threats, determine their scope, and escalate if necessary. See if
anything you find matches TTPs within the MITRE ATT&CK Framework.


5. Response
● Goal: Mitigate any confirmed threats.
● Activity: Work with security teams to contain, remove, and recover from the threat.


6. Documentation
● Goal: Record your findings and learn from them.
● Activity: Document what you found and use it to improve future hunts and defenses.


7. Improvement
● Goal: Improve your security posture or refine your methods for the next hunt.
● Activity: Adjust strategies and tools based on what worked or didn’t.
○ Anything we could have done to prevent the thing we hunted for? Any way we could have
improved our hunting process?





Notes / Findings:


Timeline Summary and Findings:


Windows-Target-1 has been internet facing for serveral months:


DeviceInfo
| where DeviceName == "windows-target-1"

| where IsInternetFacing == true

| order by Timestamp desc





Last internet facing time: 2025-03-30T19:18:40.578452Z
Several bad actors have been discovered attempting to logon to the target machine


DeviceLogonEvents


| where LogonType has_any ("Network","Interactive","RemoteInteractive","Unlock")


| where ActionType == "LogonFailed"

| where isnotempty(RemoteIP)

| summarize Attempts = count() by ActionType, RemoteIP, DeviceName

| order by Attempts



![Inter2](https://github.com/user-attachments/assets/4673b17a-08c3-4c9a-99a0-95f2e4995092)


---------------


The top 5 logon attempt IP addresses have not been able to successfully break into the VM:


let RemoteIPsInQuestion = dynamic(["218.92.0.187","218.92.0.186", "58.33.67.164", "185.7.214.14"]);


DeviceLogonEvents


| where LogonType has_any ( "Network", "Interactive","RemoteInteractive","Unlock")


| where ActionType == "LogonSuccess"


| where RemoteIP has_any (RemoteIPsInQuestion)


<Query no results>


-------------------------------------------


The only successful remote/network logons in the last 30 days was for the user "labuser" account(14total)


DeviceLogonEvents


| where DeviceName == "windows-target-1"


| where LogonType == "Network"


| where ActionType == "LogonSuccess"


| where AccountName == "labuser"


| summarize count()


There was zero (0) failed logons for the labuser account indicating thatna brute force attempt for this account
didnt take place and a 1 time password guess is unlikely


------------------------------


We checked all of the successful login IP addresses for the 'labuser' account to see if any of them were
unusual or from an unexpected location. All were normal.


DeviceLogonEvents


| where DeviceName == "windows-target-1"


| where LogonType == "Network"


| where ActionType == "LogonSuccess"


| where AccountName == "labuser"


| summarize LogonCount = count()by DeviceName, ActionType, AccountName, RemoteIP


![Inter3](https://github.com/user-attachments/assets/d4c47f75-1864-4795-a6c2-66f08e3f1d0c)


--------





Though the device was exposed to the internet and clear brute force attempts have taken place there is no

evidence of a successfull brute force logon or unauthorized

access from the legitimate account 'labuser'

Relevant MITRE ATT&CK TTPs:

-T1190: Exploit Public-Facing Application (due too the internet-facing nature of the machine)

-T1178: Valid Accounts (successful logons by legitmate account 'labuser')

-T1110: Brute Force (failed logon attempts from multiple IP addresses')

-T1587: Develop Capabillities:Exploit Code (indirect inference from multiple bad actors attempting to log in)

------
Response Actions:
Hardened the NSG attached to windows-target-1 to allow only RDP traffic from specific endpoints (no public
internet access)
Implemented account lockout policy
Implemented MFA
