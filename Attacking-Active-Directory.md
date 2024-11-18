This article is basicly my notes but boosted by chat gpt and redacted by me from TCM course titled "Practical Ethical Hacking - The Complete Course" 
# Initial Attack Vectors
In penetration testing and red team engagements, understanding initial attack vectors is essential for identifying potential weaknesses in a network's security posture. These vectors represent entry points that attackers can exploit to gain unauthorized access to systems. This section covers several attack methods, including IPv6 DNS takeover, LLMNR poisoning, and SMB relay attacks. While some of these techniques may be older or less common in modern environments, they remain important to understand for a comprehensive security assessment.                                  

In this section we’ll explore several common attack techniques:
- IPv6 DNS Takeover: Using mitm6, attackers exploit IPv6 misconfigurations to poison DNS requests, redirect traffic, capture credentials, and relay NTLM hashes to escalate attacks to domain controller access.

- LLMNR Poisoning: Attackers can spoof LLMNR responses to capture credentials or redirect traffic when DNS fails. Disabling LLMNR helps prevent this attack.

- SMB Relay: By intercepting SMB authentication traffic, attackers can relay credentials to services like LDAP or the domain controller. Mitigate this by enforcing SMB signing, disabling NTLM, and using account tiering.
## LLMNR Poisoning

Link-Local Multicast Name Resolution (LLMNR) is a protocol used for name resolution in Windows environments, allowing devices to resolve hostnames when DNS queries fail. However, it is vulnerable to poisoning attacks, especially in Active Directory networks. Here's a brief overview:

### How It Works:

1. Vulnerability: When a machine cannot resolve a hostname via DNS, it broadcasts an LLMNR query to the local network.
2. Exploitation: An attacker on the same subnet can intercept this query and respond with a fake answer, directing the victim to the attacker's machine.
3. Credential Theft: The victim system may attempt to authenticate with the attacker's machine, sending hashed credentials (e.g., NTLMv2). These hashes can be captured and cracked offline to retrieve plaintext credentials.                              

### Mitigation Steps

Important:
- Disable LLMNR and NBNS: These protocols can be turned off via Group Policy.

If company cant disable for some reason:

- Use Strong Passwords: This makes it harder to crack NTLM hashes. (at least 14 characters and limit common word usage)
- Require Network Access controll: This limits unauthorized devices from interacting with critical systems and services.

## SMB Relay 

An SMB Relay attack targets the Server Message Block (SMB) protocol, which is used for file sharing, printer access, and other network services in Windows environments. The attack allows an attacker to relay authentication requests from a victim machine to a target machine, enabling unauthorized access to network resources.

### How SMB Relay Works:

1. Intercepting SMB Traffic: The attacker sets up a rogue SMB server on the network or intercepts legitimate SMB traffic. When a victim machine attempts to authenticate to a service (e.g., file shares), the attacker captures the authentication request.
2. Relaying the Request: The attacker then forwards the captured authentication request to a different target machine on the network that is accessible. This target machine believes the request is legitimate and grants the attacker access, often using the victim's credentials.
3. Authentication and Access: Once the target machine accepts the credentials, the attacker can escalate their privileges or gain unauthorized access to sensitive files or services.

### Mitigation Steps:

- Enable SMB Signing on All Devices: Ensure SMB signing is enabled across all devices to prevent attackers from tampering with or relaying SMB traffic.
- Disable NTLM Authentication on the Network: Disable NTLM authentication in favor of Kerberos to reduce the attack surface for SMB relay attacks.
- Account Tiering: Implement a tiered access model to isolate sensitive accounts, minimizing the impact of a compromised account.
- Local Admin Restriction: Restrict the use of local administrator accounts and enforce the principle of least privilege to limit the potential damage from compromised credentials.

## IPv6 DNS Takeover 

An IPv6 DNS takeover attack, facilitated by the mitm6 tool, allows an attacker to manipulate DNS traffic over an IPv6 network. This attack can be leveraged to gain unauthorized access to domain controllers and escalate privileges by combining DNS spoofing with NTLM relay techniques.

**Warning**: This tool can cause disruptions to the DNS infrastructure if run for too long, potentially leading to a Denial of Service (DoS) or overload on DNS servers. It is recommended to run mitm6 for a maximum of 10 minutes to avoid impacting DNS stability.
### How the Attack Works:

1. Tool Setup: The attacker runs the mitm6 tool on the network, which performs a Man-in-the-Middle (MITM) attack by intercepting DNS requests from victim machines. The tool impersonates a DNS server and manipulates DNS queries, directing the victim to attacker-controlled servers.
2. Credential Capture: When a victim logs into the network, the attacker intercepts the NTLM hash as part of the authentication process. Since NTLM authentication is used by default in many environments, the attacker can grab the NTLM hash whenever a user connects to the network.
3. LDAP Relay: Once the attacker has the NTLM hash, they can use LDAP relay to forward the authentication request to a Domain Controller. By relaying the credentials through the LDAP protocol, the attacker can gain access to domain resources and escalate their privileges.
4. Account Creation and Access: Using the NTLM relay technique, the attacker can authenticate with the domain controller and create new user accounts or gain control over existing accounts. This allows the attacker to access sensitive resources, install malware, or escalate further within the network.
5. Combining mitm6 with ntlmrelayx: The attacker can combine the capabilities of mitm6 with ntlmrelayx, a tool designed to relay NTLM authentication to various services (including LDAP and SMB). This allows for further exploitation, such as creating new accounts, gaining administrative access, or leveraging other vulnerabilities within the domain.
### Mitigation Steps:

- Block DHCPv6 Traffic and Router Advertisements: To prevent mitm6 attacks, block DHCPv6 traffic and incoming router advertisements in Windows Firewall via Group Policy, especially in IPv4-only environments where IPv6 is not needed. This prevents rogue DNS servers from being advertised on the network. Set the following predefined rules to Block instead of Allow:                                                     
    (Inbound) Core Networking - Dynamic Host Configuration Protocol for IPv6 (DHCPv6-In)                                                      
    (Inbound) Core Networking - Router Advertisement (ICMPv6-In)                                                     
    (Outbound) Core Networking - Dynamic Host Configuration Protocol for IPv6 (DHCPv6-Out)                                                     
- Disable WPAD: If WPAD (Web Proxy Auto-Discovery Protocol) is not in use internally, disable it via Group Policy and by stopping the WinHttpAutoProxySvc service. WPAD can be exploited to redirect traffic through malicious proxy servers, increasing the risk of man-in-the-middle attacks.
- Enable LDAP Signing and Channel Binding: To mitigate risks associated with LDAP and LDAPS relaying, enable both LDAP signing and LDAP channel binding. These features help protect LDAP communications from tampering and unauthorized relaying, making it more difficult for attackers to intercept and manipulate traffic.
- Protect Administrative Accounts: Consider adding administrative users to the Protected Users group or marking them with the "Account is sensitive and cannot be delegated" flag. This prevents attackers from impersonating these accounts through delegation, reducing the risk of privilege escalation and unauthorized access to critical resources.
## Passback Attacks:

A passback attack involves exploiting vulnerabilities in the way authentication tokens or sessions are handled by a server. The attacker intercepts the token, then attempts to "pass it back" to the server from a different client or machine to impersonate a legitimate user.                                                                                         

While passback attacks are an older technique and not commonly seen in modern environments due to improvements in authentication protocols and token security, they are still worth knowing. Understanding the potential for passback attacks can help in securing legacy systems and recognizing unusual behavior that may indicate a vulnerability.
# Post-Compromise Attacks 
## Pass attacks
Pass-the-Hash and Pass-the-Password attacks are methods that can be performed after obtaining user credentials. Using tools like CrackMapExec, we can check if the user we've compromised has local admin rights on other machines within the network. This allows us to see if we can access more SMB shares or systems that were previously out of reach, expanding our foothold and moving laterally across the network.
## Mitigation Steps:
While it’s difficult to completely prevent Pass-the-Hash and Pass-the-Password attacks, there are several strategies to make them more challenging for attackers:
- Limit Account Reuse: Avoid reusing the same local admin password across multiple systems to reduce the impact of a compromised password. Also, disable Guest and Administrator accounts to prevent easy exploitation. Implement the principle of least privilege by limiting the number of users with local admin rights.
- Utilize Strong Passwords: Ensure that passwords are long (preferably 14 characters or more) and avoid common words or predictable phrases. Using long, complex passwords significantly reduces the chances of an attacker guessing or cracking them.
- Privilege Access Management (PAM): Implement PAM practices, which involve checking in and out sensitive accounts when needed. Automate the rotation of passwords each time they are checked out and checked back in. This limits the effectiveness of Pass-the-Hash or Pass-the-Password attacks by ensuring that stolen credentials are constantly rotated, making it harder for attackers to use them successfully.
## Kerberoasting:
Kerberoasting is an attack that targets service accounts in a Kerberos authentication environment. It works by requesting service tickets (TGS - Ticket Granting Service) for service accounts that are configured to use weak or easily guessable passwords. Once the attacker has obtained these service tickets, they can be cracked offline to retrieve the plaintext passwords of the service accounts.
### How Kerberoasting Works
The key steps in a Kerberoasting attack are:
1. Requesting Service Tickets: The attacker requests service tickets for service accounts that are marked as "servicePrincipalName" (SPN) in the Active Directory (AD) environment. These accounts are typically used to run network services (e.g., SQL Server, IIS).
2. Cracking the Tickets: After obtaining the service tickets, the attacker can attempt to crack them offline using tools like Hashcat or John the Ripper. Since these tickets are encrypted using the service account's password hash, a weak or simple password can be cracked relatively easily.
3. Compromising the Account: Once the attacker successfully cracks the password, they can use it to authenticate to the service and gain unauthorized access to the associated resources.

![image](https://github.com/user-attachments/assets/7395c634-b0bb-4eef-95f1-815bea898231)

### Mitigation Steps:
- Use Strong Passwords for Service Accounts: Ensure that service accounts are configured with strong, complex passwords—preferably 20+ characters in length, containing a mix of letters, numbers, and special characters. The strength of these passwords reduces the likelihood of successful cracking during a Kerberoasting attack.
- Enforce Least Privilege: Apply the least privilege principle to service accounts by limiting their permissions to the minimum necessary for the service to function. Service accounts should not have elevated privileges, as excessive permissions can give attackers greater access if they compromise the service account's credentials. Reducing the attack surface for these accounts makes them less attractive targets for attackers.
## Tocken Impersonation
Token Impersonation is an attack technique where an attacker takes advantage of an existing authentication token to impersonate a legitimate user or service. This typically occurs when an attacker gains access to a token that allows them to impersonate a higher-privileged user or service, potentially giving them unauthorized access to resources or systems within the network.

Tokens are often used in environments like Kerberos or NTLM authentication to represent a user's identity and permissions. In Token Impersonation, the attacker essentially "hijacks" or forges a token to gain the same access as the legitimate user or service.
### How Tocken Impersonation Works:
1. Token Harvesting: An attacker may obtain a token by compromising a system where the user is authenticated, either through techniques like pass-the-hash, credential dumping, or exploiting weak permissions.
2. Impersonating a User or Service: Once the attacker has obtained a valid token, they can use it to impersonate the victim's session, granting them access to resources the victim can access.
3. Escalating Privileges: If the attacker is able to acquire a token from a high-privileged account (e.g., Administrator or Domain Admin), they can use it to escalate their privileges across the network and gain unauthorized control of other systems and services.
### Mitigation Steps:
- Limit User/Group Token Creation Permission: Restrict who can create or manage user and group tokens. Only allow trusted administrators and systems to generate tokens, reducing the chance of an attacker gaining access to privileged tokens.
- Account Tiering: Implement an account tiering strategy, where high-privilege accounts (such as Domain Admins) are kept on isolated systems with limited access to regular user resources. This prevents attackers from easily moving laterally between accounts with varying privilege levels.
- Local Admin Restriction: Limit the use of local admin privileges across the network. Restricting local admin access helps prevent attackers from using compromised accounts to escalate privileges or create malicious tokens that could be used to impersonate other users or services.
## LNK File Attacks
LNK File Attacks exploit Windows shortcut files (.LNK), which are typically used to point to executables or other resources. What makes this attack particularly dangerous is that the user does not even need to click on the LNK file for the attack to be triggered. Simply viewing or interacting with a folder containing a malicious LNK file can execute the malicious payload embedded in the shortcut. This is because LNK files can be designed to automatically run code when their associated folder or directory is opened.
### How LNK File Attacks Work:
1. Malicious LNK File Creation: An attacker creates a malicious LNK file that points to an executable or script, like a PowerShell script or malicious executable. These files can be disguised to look like harmless documents or folders.
2. User Interaction (No Click Required): The attacker places the malicious LNK file in a location where the user will interact with it, such as an email attachment, shared network folder, or USB drive. Importantly, the user doesn't need to click the LNK file for it to execute. Simply opening the folder or directory containing the LNK file may be enough to trigger the execution of the payload.
3. Malicious Payload Execution: Once the LNK file is accessed (even by simply opening the folder), it runs the payload, leading to actions such as code execution, privilege escalation, or malware installation on the victim’s machine.
### Mitigation Steps:
- Restrict LNK File Creation: Limit the ability of users, particularly those with low privileges, to create LNK files, reducing the risk of attackers creating malicious shortcuts.
- Educate Users: Since LNK files often rely on social engineering, it is crucial to educate users to avoid opening suspicious files or folders, especially from untrusted sources.
## GPP / cPassword Attacks
This is an old attack, unlikely to be encountered in the wild, but still worth knowing about.                                                    
GPP (Group Policy Preferences) / cPassword Attacks refer to the exploitation of sensitive information stored in Group Policy Preferences (GPP) in Windows environments. Group Policy Preferences are a feature in Active Directory that allows administrators to manage configuration settings for users and computers. However, GPP also has a vulnerability where sensitive information, such as passwords, was stored in plaintext or easily reversible formats in older Windows versions, specifically in the cpassword attribute.
### How GPP / cPassword Attacks Work:
1. Group Policy Preferences and cPassword: In older versions of Windows (before the security patch in 2014), administrators could use GPP to configure settings like mapped drives, scheduled tasks, and local user accounts. In doing so, GPP would allow passwords to be set for local accounts as part of the policy. These passwords were stored in the cpassword attribute in the Group Policy Preferences XML file.
2. Exploitation: The cpassword field was encrypted, but it used a weak encryption algorithm, making it possible for an attacker with access to the Group Policy object (GPO) to extract and decrypt the password. If an attacker has access to the GPO (e.g., through misconfigured permissions or privileged access), they can retrieve the password and use it to escalate privileges or move laterally within the network.
3. Password Decryption: Tools like PowerShell scripts or GPPDecrypt can be used to extract the password from the GPP XML files. The password can then be used to access services, escalate privileges, or further compromise the network.
### Mitigation Steps:
- Patch: Ensure systems are updated with the fix provided in KB2962486 to address the vulnerability in GPP.
- In reality: delete any old GPP XML files stored in the SYSVOL folder, as they may still contain plaintext passwords that can be exploited.
## Credential Dumping with Mimikatz
Mimikatz needs to be heavily obfuscated, as most antivirus programs will detect it.

Credential dumping refers to the technique used by attackers to extract and collect sensitive authentication credentials, such as usernames and passwords, from a compromised system. One of the most well-known tools for credential dumping is Mimikatz.

Mimikatz is a powerful post-exploitation tool that can be used to extract plaintext passwords, password hashes, Kerberos tickets, and other sensitive information stored in memory. It is widely used by penetration testers, red teamers, and attackers to escalate privileges or pivot within a network.
### How Mimikatz Works:
1. Memory Dumping: Mimikatz can directly interact with the Windows LSASS (Local Security Authority Subsystem Service) process, which stores credentials in memory. By dumping the contents of LSASS, Mimikatz can extract passwords and hashes of users currently logged into the system.
2. Pass-the-Hash (PTH) and Pass-the-Ticket (PTT): Mimikatz can be used to perform Pass-the-Hash or Pass-the-Ticket attacks. In a Pass-the-Hash attack, the attacker uses extracted NTLM hashes to authenticate to remote systems without needing the plaintext password. In Pass-the-Ticket, Kerberos tickets are extracted and reused to authenticate to services.
3. Extracting Passwords and Hashes: Mimikatz can retrieve credentials such as:
Plaintext passwords (if they are cached or available in memory).
NTLM hashes (which can be used for further attacks like Pass-the-Hash).
Kerberos tickets (useful for Kerberos-based attacks like Golden Ticket or Silver Ticket attacks).
4. Kerberos Ticket Extraction: Mimikatz can extract Kerberos tickets (TGTs and service tickets) from memory, enabling attackers to impersonate users and access network resources, especially if they have Kerberos keys or can forge tickets.
## Golden Ticket Attack 
A Golden Ticket attack is a powerful method used to gain long-term access to an Active Directory (AD) environment. It leverages Kerberos authentication by forging valid Kerberos Ticket-Granting Tickets (TGTs). These forged tickets allow attackers to impersonate any user, including domain admins, and access virtually any resource in the domain.
### How Golden Ticket Attack Work:
1. Prerequisites:                                                                     
    - The attacker needs the KRBTGT account's NTLM hash from the domain controller (DC).
    - Access to a tool like Mimikatz to craft the ticket.
2. Forging the Ticket:                                                                   
    - Mimikatz is used to create a fake TGT using the KRBTGT hash.
    - This fake TGT is cryptographically valid and will be accepted by the domain controller as authentic.
3. Using the Golden Ticket:                                                           
    - The attacker can impersonate any user, including high-privilege accounts like domain admins.
    - They gain unrestricted access to AD resources, such as file shares, databases, and sensitive systems.
4. Persistence:                                               
    - Since the KRBTGT account's hash rarely changes, the attacker can maintain access indefinitely unless the hash is rotated twice (recommended for mitigation).
### Mitigation Steps:
1. Rotate the KRBTGT Account Key:
   - Perform a double reset of the KRBTGT account password to invalidate forged tickets. Follow Microsoft's guidelines for securely rotating this account.

2. Implement Least Privilege:
   - Restrict the use of domain admin accounts and limit their exposure.
3. Enable LSA Protection:
   - Protect LSASS (Local Security Authority Subsystem Service) to prevent credential dumping.
4. Secure Domain Controllers:
   - Apply strict access controls and ensure DCs are patched and isolated from less secure network segments.
## Silver Ticket Attack
A Silver Ticket attack involves forging a Kerberos Service Ticket (TGS) to gain unauthorized access to a specific service within the domain, such as SQL Server or file shares. Unlike Golden Tickets, Silver Tickets use the hash of a service account (e.g., svc_sql) instead of the KRBTGT hash and are harder to detect due to bypassing domain controller logging.
# Additional Things
## ZeroLogon
A Zerologon attack exploits a critical vulnerability in the Netlogon protocol (CVE-2020-1472) to reset the domain controller's machine account password. This grants attackers full domain admin privileges, enabling complete control over the domain. However, running this attack can destabilize the domain controller, potentially corrupting or deleting the entire domain, making it highly dangerous to execute.
## A PrintNightmare
A PrintNightmare attack (CVE-2021-34527) exploits vulnerabilities in the Windows Print Spooler service, allowing attackers to achieve remote code execution or escalate privileges to SYSTEM. By exploiting improper privilege checks during printer driver installations, an attacker can execute arbitrary code or perform lateral movement. This makes it a critical vulnerability often used to gain full control over Windows systems.
### Detection 
To detect vulnerability simply run this command in terminal using rpcdump:
```
rpcdump.py @<IP> | egrep 'MS-RPRN|MS-PAR'
```

![image](https://github.com/user-attachments/assets/a9ff68e7-5985-44c9-8c5f-f0d15806ae4c)

If output is like shown on screen machine is vulnerable
## EvilCups
I will write about this vulnerability in detail in another post but for now brief overwiew and also this is added by me becouse it is recent and wasnt included in TCM course.
EvilCups targets misconfigured CUPS servers to send malicious print jobs that can lead to unauthorized access or remote code execution. The attack exploits poor access controls in CUPS, often on Linux/Unix systems, allowing attackers to inject payloads. To mitigate, restrict access to trusted IPs, enable authentication, and regularly update CUPS.                                     

Thats all for now thanks for attention to the one person that is reading this.
