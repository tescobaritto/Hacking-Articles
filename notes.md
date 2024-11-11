theese are just my notes, dont mind:
# tricks
## Virutal Environment:
activate:
```
python -m venv venv
.\venv\Scripts\activate
```
end:
```
deactivate
```
## Tmux:
accidentally closed tmux terminal
```
tmux ls
tmux attach-session -t <session name>
```
or when there is only one session:
```
tmux attach
```
# Hacking
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
## LDAP:
```
nxc ldap <IP> -d <Domain> -u '<username>' -p '<password>' -M group-mem -o group='Remote Management Users'
```
