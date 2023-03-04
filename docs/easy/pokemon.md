
[TryHackMe Link](https://tryhackme.com/room/pokemon){ .md-button }

!!! example "Description"

    <p id="desc" style="font-size:15px"></p>

Pokemon Themed CTF with 4 hidden flags:

* Find the Grass-Type Pokemon

* Find the Water-Type Pokemon

* Find the Fire-Type Pokemon

* Who is Root's Favorite Pokemon?

## <b>Scanning</b>

* Assigned IP address: &nbsp; <b id="ip" style="color:purple"></b>
  
* Open Ports: 

| <p style="font-size:14px; color: black">PORT</p>      | <p style="font-size:14px; color: black">SERVICE</p> |  <p style="font-size:14px; color: black">DESCRIPTION                          |
| :---------: | :---------: | :----------------------------------: |
| <p id="p1" style="font-size:14px; color: purple"></p>      | <p id="s1" style="font-size:14px; color: purple"></p>  |<p id="d1" style="font-size:14px; color: purple"></p>   |
| <p id="p2" style="font-size:14px;  color: purple"></p>     | <p id="s2" style="font-size:14px; color: purple"></p>  |<p id="d2" style="font-size:14px; color: purple"></p> |


* Nmap Report:
  ```s linenums="1" hl_lines="6 11"
    # Nmap 7.93 scan initiated Fri Mar  3 21:14:45 2023 as: nmap -sC -sV -O -oN nmap.txt 10.10.155.239
    Nmap scan report for 10.10.155.239
    Host is up (0.17s latency).
    Not shown: 998 closed tcp ports (reset)
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 581475691ea9595fb23a691c6c785c27 (RSA)
    |   256 23f5fbe757c2a53ec226290e74db37c2 (ECDSA)
    |_  256 f19bb58ab929aab6aaa2524a6e6595c5 (ED25519)
    80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    |_http-title: Can You Find Them All?
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.93%E=4%D=3/3%OT=22%CT=1%CU=30093%PV=Y%DS=5%DC=I%G=Y%TM=6402A9BC
    OS:%P=aarch64-unknown-linux-gnu)SEQ(SP=107%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=
    OS:A)OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M5
    OS:05ST11NW7%O6=M505ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B
    OS:3)ECN(R=Y%DF=Y%T=40%W=F507%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S
    OS:+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=
    OS:)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%
    OS:A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%
    OS:DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=
    OS:40%CD=S)

    Network Distance: 5 hops
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Fri Mar  3 21:15:24 2023 -- 1 IP address (1 host up) scanned in 38.73 seconds

  ```

## <b>Enumeration & Shell Access</b>

I started my enumeration from the webserver at port 80 where I discovered that the default pages had been altered. To identify the custom changes, I used a python script that I had written, called [eastereggs](https://github.com/VasanthVanan/CTF-EasterEggs-Default-Pages). 

!!! tip "Eastereggs.py"
    <span>This python script compares the default Apache welcome page with the webpage of your CTF Box (which also serves Apache), highlights the differences between the two HTML files, and prints the added, removed, or altered content.</span>

<img id="image1" />

I found that the creator of the game had added a few JS scripts to console log an array with pokemon characters. 

<img id="image2" />

Additionally, the creator had left a strange message with two keywords that initially confused me. 

```html
<pokemon>: <REDACTED>
```

At first, I suspected the keywords might lead to a hidden directory, but that was not the case. 

<img id="image3" />

Next, I thought they might be associated with a JavaScript function that had to be invoked via console, but that also didn't work. 

<img id="image4" />

Eventually, I discovered that the two keywords were credentials for the SSH service at port 22, which made it easy for me to gain access without having to mess up for initial foothold.

<img id="image5" />

Once I logged in to SSH, I traversed the user's home folders and found a strange ZIP file named **P0kemon** on the desktop. I suspected that one of the flags might be inside. However, to my surprise, the flag was encoded in HEX in the following file location. 

```t
/Desktop/P0kEmOn/grass-type.txt
```

After decoding it, I found the flag for **`grass-type`**. Interestingly, I found a similar pattern for all flags, as they were stored in **`.txt`** files.

To locate the other three flags, I used the find command to ensure I grabbed all the text files. 

```s
find / -name "*.txt" 2>/dev/null 1>output.txt
```

!!! danger "Flag Locations"
    <span>/etc/why_am_i_here?/fire-type.txt</span>

    <span>/var/www/html/water-type.txt</span>

    <span>/home/roots-pokemon.txt</span>
    

While **`fire-type.txt`** had another flag that could be decoded using **base64**, 

```s
cat /etc/why_am_i_here?/fire-type.txt | base64 --decode
```

I was unable to extract the flag from **`water-type.txt`**. So, I moved on to escalate my privileges.

## <b>Privilege Escalation</b>

To acquire access to the user **Ash**, I ran ***linpeas.sh*** and noticed that **127.0.0.1:631** was open locally. I decided to use the **[Chisel](https://github.com/jpillora/chisel)** tool for port forwarding and explore the private service to acquire the credentials of Ash. 

<b>Chisel Server (Your Machine)</b>

```s
chisel server -p 8003 --reverse 
```

<b>Chisel Client (CTF Machine)</b>

```s
./chisel client 10.17.3.217:8003 R:631:127.0.0.1:631
```

!!! question "Explanation"

    <span>This command uses the Chisel tool to establish a reverse proxy connection between a server and a client. The Chisel server is created on port 8003 using the **--reverse** flag, while the Chisel client connects to the server at IP address **10.17.3.217** on port **8003**. Traffic from the client to **port 631 on the remote server** is forwarded to **port 631 on the client's machine** (127.0.0.1), allowing the client to interact with the remote service as if it were running on the client's machine.</span>


However, I ended up getting an unrelated service that would not contribute to my local privilege escalation.

<img id="image6" />

Later, I explored other folders in the home directory, I discovered a C++ content in the **/Videos** subfolder containing hidden Ash credentials. 

**```Videos/Gotta/Catch/Them/ALL\!/Could_this_be_what_Im_looking_for?.cplusplus```**

```cpp
# include <iostream>

int main() {
        std::cout << "ash : [REDACTED]"
        return 0;
}
```

I then switched user to Ash and used **sudo su** to become root. 

<img id="image7" />

I found the answer to `"Who is Root's Favorite Pokemon"` in 

```
/home/roots-pokemon.txt
```

!!! success "Last Flag"

    <span>At a later stage, I referred other's walkthrough and learned that `Ceaser-Cipher` were used for encoding the `Water-Type.txt`. So, I substituted the characters and found the last flag too.</span>


<script>

// JSON object
const data = {
    "desc": "This room is based on the original Pokemon series. Can you obtain all the Pokemon in this room?",
    "ip":  "10.10.155.239",
    "ports": "22/tcp,ssh,OpenSSH 7.2p2 Ubuntu 4ubuntu2.8;80/tcp,http,Apache httpd 2.4.18",
    "difficulty":"easy",
    "id": "11"
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