
[TryHackMe Link](https://tryhackme.com/room/biohazard){ .md-button }

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
  ```s linenums="1" hl_lines="6 7 12"

    # Nmap 7.93 scan initiated Thu Oct 12 11:22:55 2023 as: nmap -sC -sV -O -oN nmap.sh 10.10.75.175
    Nmap scan report for biohazard.thm (10.10.75.175)
    Host is up (0.31s latency).
    Not shown: 997 closed tcp ports (reset)
    PORT   STATE SERVICE VERSION
    21/tcp open  ftp     vsftpd 3.0.3
    22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 c903aaaaeaa9f1f40979c0474116f19b (RSA)
    |   256 2e1d83116503b478e96d94d13bdbf4d6 (ECDSA)
    |_  256 913de44fabaae29e44afd3578670bc39 (ED25519)
    80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
    |_http-server-header: Apache/2.4.29 (Ubuntu)
    |_http-title: Beginning of the end
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.93%E=4%D=10/12%OT=21%CT=1%CU=41647%PV=Y%DS=5%DC=I%G=Y%TM=65280F
    OS:7F%P=aarch64-unknown-linux-gnu)SEQ(SP=104%GCD=1%ISR=10E%TI=Z%CI=I%II=I%T
    OS:S=A)OPS(O1=M508ST11NW6%O2=M508ST11NW6%O3=M508NNT11NW6%O4=M508ST11NW6%O5=
    OS:M508ST11NW6%O6=M508ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=6
    OS:8DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M508NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A
    OS:=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%
    OS:Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=
    OS:A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=
    OS:Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%
    OS:T=40%CD=S)

    Network Distance: 5 hops
    Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Thu Oct 12 11:23:43 2023 -- 1 IP address (1 host up) scanned in 48.37 seconds

  ```

In contrast to other rooms, this room had so many questions in the sense I somehow felt as a walkthrough room. Some of these questions and flags were intuitive, while others was bit challenging. In this walkthrough, I would like to skip the simpler tasks and describe on those that appeared more difficult. 

## <b>Enumeration</b>

Initially, I accessed the website hosted on `port 80 (HTTP)`, and it led to a plenty of redirects, each pointing towards different flags. It was hard to keep track of the pages I visited and also it was intuitive that anyone can just go through the instructions and move forward to get the flags.  However, Be familiar with the following scenarios:

- clues can be hidden within the source code of the HTML files, so be sure to visit `view-page-source`.
- Encrypted keys may be divided into two or three segments. The task is to gather all the flags and combine them to obtain the final key.
- There will be instances where you'll need to decrypt messages using methods like `ROT13`, `Base32`, and `Base64`, and sometimes even use the `Vigenère cipher` with magical words.

<img id="image1" /> <br><br> <img id="image2" />

For easier access, I found a page at 

```
http://10.10.75.175/artRoom/MansionMap.html
```

which conveniently provided a list of rooms available for exploration:

```
/diningRoom/
/teaRoom/
/artRoom/
/barRoom/
/diningRoom2F/
/tigerStatusRoom/
/galleryRoom/
/studyRoom/
/armorRoom/
/attic/
```

## <b>Initial Access</b>

After gathering the low-hanging flags using the aforementioned strategies, I successfully obtained the FTP `username` and `password`. With these credentials, I logged in and downloaded all the available files, which included images, a GPG file, and a text file.

```bash 
.
├── 001-key.jpg
├── 002-key.jpg
├── 003-key.jpg
├── _003-key.jpg.extracted
│   ├── 78A.zip
│   └── key-003.txt
├── helmet_key.txt.gpg
├── important.txt
├── key-001.txt
└── nmap.sh
```

!!! info "Pentesting Practice"
    <span>When encountering suspicious image files, It is a good practice to identify their file structure, content, and the potential presence of steganographic data.</span>

 Often, there would be some juicy information hidden within these files. I utilized [this resource](https://book.hacktricks.xyz/crypto-and-stego/stego-tricks) to find various pieces of information from files like `001-key.jpg`, `002-key.jpg` and `003-key.jpg`. Through a combination of 

 - `steghide` for 001-key.jpg, 
 - `exiftool` for 002-key.jpg, and 
 - `binwalk` for 003-key.jpg, 

  <img id="image3" />

 I gathered all the flags and combined them to obtain the final key. This final key is the private key used to encrypt the `helmet_key.txt.gpg` GPG file.

 <img id="image4" />

Subsequently, I decrypted the GPG file using the following command. 

```s 
gpg -d helmet_key.txt.gpg
```


Also, `important.txt` text file contained the following message:

```
Jill,

I think the helmet key is inside the text file, but I have no clue on decrypting stuff. Also, I come across a /hidden_closet/ door but it was locked.

From,
Barry
```

In {++http://10.10.75.175/studyRoom/++}, I found a file that provided me the username for SSH service. similarly password was found on {++http://10.10.75.175/hidden_closet/++}

Upon logging in with these credentials, I discovered the `chris.txt` file within the hidden folder `jail cell`. Two other users, `Hunter` and `Weasker`, were present on the system. 

To acquire Weasker's password, I used information about a key and cipher left behind at `http://10.10.75.175/hidden_closet/`. 

 <img id="image5" />

I decrypted using Vigenère cipher. Later, I ran the provided SSH information and accessed the weasker account.Finally, while navigating the system, I found - the ultimatum form's name and the root.txt flag.

 <img id="image6" />


<script>

// JSON object
const data = {
    "desc": "A CTF room based on the old-time survival horror game, Resident Evil. Can you survive until the end?",
    "ip":  "10.10.75.175",
    "ports": "21/tcp,ftp,vsftpd 3.0.3;22/tcp ,  ssh,OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux protocol 2.0);80/tcp ,  http,    Apache httpd 2.4.29 ((Ubuntu))",
    "difficulty":"medium",
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