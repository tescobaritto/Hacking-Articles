This article will evolve over time
# SMB (Server Message Block)
Working on port 445                       

SMB is a file-sharing protocol that allows applications and users to read/write/delete files on a remote computer. It can also provide access to network resources such as printers. It is also used to carry transaction protocols for authenticated inter-process communication.

There are two types of SMB shares administrative($) used to manage and access computer and regular ones used to share files.

Here is example of what smb share look like listed with smbclient:
```
smbclient -L //172.19.0.2/
```
```
Sharename       Type      Comment
---------       ----      -------
IPC$            IPC       IPC Service (Example Server)
C$              Disk      C Drive
print$          Disk      Printer Drivers
ADMIN$          Disk      Remote Admin
public          Disk      Public share
```
Shares with dolar sign added after sharename are administrative ones.

On modern Windows systems, SMB can run directly over TCP/IP on port 445. On other systems, we may find that some services and applications are using port 139. This means that SMB is running with NetBIOS over TCP/IP.

All SMB versions are backwards-compactable, this means that devices running newer versions of Windows can easily communicate with devices that have older Microsoft OS installed

### SMB Versions:
- CIFS (Pre-SMB) – Microsoft Windows NT 4.0 in 1996.
- SMB-1.0 / SMB1 – Windows 2000, Windows XP, Windows Server 2003 and Windows Server 2003 R2.
- SMB-2.0 / SMB2 – Windows Vista and Windows Server 2008.
- SMB-2.1 / SMB2.1 – Windows 7 and Windows Server 2008 R2.
- SMB-3.0 / SMB3 – Windows 8 and Windows Server 2012.
- SMB-3.02 / SMB3 – Windows 8.1 and Windows Server 2012 R2.
- SMB-3.1 – Windows Server 2016 and Windows 10.
### Default shares:
Admin shares
- ADMIN$ - Used for remote administration
- C$ - Every disk volume is shared as administrative share.
- IPC$ - An administrative share that provides access to named pipes for inter-process communication, enabling remote administration and access to shared resources.               

Domain Controller shares:
- NETLOGON - Used to store the Group Policy logon script, and possibly other files.
- SYSVOL -  A set of files and folders that reside on the local hard disk of each domain controller in a domain and that are replicated by the File Replication service (FRS).
## Enumerating SMB
### smbclient 
smbclient allows us to list shares and connect to them, if we would want to list shares for anonymous access we would supply that command:
```
smbclient -L //<IP>/ -N
```
### smbmap
there is also better way to enumerate shares with smbmap, especially when we have some credentials becouse smbmap let us see to what shares we have read, write or execute permissions:
```
smbmap -H <IP> -u <username> -p <password>
```

![image](https://github.com/user-attachments/assets/d12bea25-65b4-4a05-b21f-34dc4ac09f8d)

Here is smbclient for comparison:

![image](https://github.com/user-attachments/assets/721c0ee0-04b6-4278-9bdb-16e6f67ff97c)

Smbclient is a tool designed with administrators in mind, whereas smbmap is targeted more for security professionals and hackers.
### crackmapexec
Crackmapexec (often used for post-compromise enumeration) can be very effective for checking access and permissions:

![image](https://github.com/user-attachments/assets/1a2be2a7-6701-471e-806a-3d382d373ffa)

It also tells us OS that target is running and if SMBv1 is enabled (huge attack vector becouse of eternal blue exploit)
