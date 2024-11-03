theese are just my notes, dont mind:
## Fuzzing:
```
ffuf -w <wordlist> -H "Host: <FUZZ.example.com>" -u http://<IP> -fw <words>
wfuzz -w <wordlist> -u http://<example.com>/ -H 'Host: <FUZZ.example.com>' -t 50 --hc <response>
```
## SMB:
```
smbmap -H <IP> -u <username> -p <password>
smbclient //<target_IP>/<share_name> -U <username>%<password>
```
IPC$ access:
```
rpcclient -U <username>%<password> <target_IP> -c "enumdomusers"
```
## DNS:
```
nslookup <example.com> <DNS_server_IP>
host -a <example.com>
host <example.com> <DNS_server_IP>
dig <example.com>
dig @<DNS_server_IP> <example.com> AXFR
```
## WinRm:
```
evil-winrm -i <IP> -u <username> -p'<password>'
```
