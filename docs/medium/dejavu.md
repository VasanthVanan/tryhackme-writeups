
[TryHackMe Link](https://tryhackme.com/room/dejavu){ .md-button }

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
    # Nmap 7.93 scan initiated Sat Nov  4 10:50:58 2023 as: nmap -sC -sV -O -oN nmap.sh 10.10.46.35
    Nmap scan report for 10.10.46.35
    Host is up (0.34s latency).
    Not shown: 975 filtered tcp ports (no-response), 23 filtered tcp ports (admin-prohibited)
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.0 (protocol 2.0)
    | ssh-hostkey: 
    |   3072 300f388d3bbe67f3e0caeb1c93ad1586 (RSA)
    |   256 4609662b1fd1b93cd7e1730f2f334f74 (ECDSA)
    |_  256 a8430ed2c1a9d114e09531a16294ed44 (ED25519)
    80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
    |_http-title: Dog Gallery!
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Aggressive OS guesses: Linux 5.4 (91%), Linux 3.10 - 3.13 (90%), Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Adtran 424RG FTTH gateway (86%)
    No exact OS matches for host (test conditions non-ideal).

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Sat Nov  4 10:51:50 2023 -- 1 IP address (1 host up) scanned in 52.43 seconds
  ```

## <b>Enumeration</b>

The Dejavu room presented two open ports, `SSH` and `HTTP`, both on their default ports. Upon accessing port 80, I encountered a web interface designed for showcasing dog images. It was very obivous that the developer had intended to create a dog image gallery. 

<img id="image1" />

This box was designed to provide a guided walkthrough, simplifying the process of obtaining flags by asking questions.

- {==**What page can be used to upload your own dog picture?**==}

```/upload/``` Self explanatory. To locate the page for uploading your own dog picture, I navigated to /upload/. This was a straightforward find, and I used the dirsearch tool to enumerate hidden directories.

- {==**What API route is used to provide the Title and Caption for a specific dog image?**==}

```/dog/getmetadata```. This can be found in the javascript files linked to the website. Additionally, One can check it through burp-suite as suggested in the hint section

- {==**What API route does the application use to retrieve further information about the dog picture?**==}

```/dog/getexifdata```. Similarly I captured the HTTP GET requests and analysed it.

<img id="image2" />

- {==**What attribute in the JSON response from this endpoint specifies the version of ExifTool being used by the webapp?**==}

```ExifToolVersion```

- {==**What version of ExifTool is in use?**==}

```12.23```

<img id="image3" />

- {==**What RCE exploit is present in this version of ExifTool? Give the CVE number in format CVE-XXXX-XXXXX**==}

The critical turning point of this box was the discovery of a CVE (Common Vulnerabilities and Exposures) related to `ExifTool` version `12.23`. I quickly searched online and found the relevant CVE: `CVE-2021-22204`. This CVE involved arbitrary remote code execution through Python.

<img id="image4" />

## <b>Initial Access</b>

As I went deeper into the vulnerability, I uncovered more details. The vulnerability originated from the `eval()` function in Perl, as Perl was used in ExifTool. The issue was described as 


!!! danger "Vulnerability"
    
    <p id="desc" style="font-size:15px">"Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image."</p>

I proceeded to clone the existing code from searchsploit and attempted to execute it against the target website. 

<img id="image5" />

To exploit this vulnerability, the Python code utilized the following payload to generate an image:

```python
(metadata "\c${system('id')};")
```

I then uploaded the image to the `/upload/` section and set up a listener on my end to capture the request when I accessed the image. 

<img id="image6" />

The moment I clicked on that image, I gained limited shell access as the user `dogpics`

<img id="image7" />
<img id="image8" />

 ✅ User Flag obtained. 

## <b>Privilege Escalation</b>

Subsequently, it was time to escalate privileges using existing vulnerabilities. The room had already provided a clue on how to achieve this. It guided me to exploit an `SUID binary` with `path manipulation`. In the same folder, I found a `ServerManager` binary and its associated `ServerManager` C file. 

<img id="image9" />

This was a white-box testing opportunity. I inspected the code and analyzed its behavior. It attempted to use the **system()** command in C language to run **systemctl**. 

```c linenums="1" hl_lines="29 32"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{   
    setuid(0);
    setgid(0);
    printf(
        "Welcome to the DogPics server manager Version 1.0\n"
        "Please enter a choice:\n");
    int operation = 0;
    printf(
        "0 -\tGet server status\n"
        "1 -\tRestart server\n");
    while (operation < 48 || operation > 49) {
        operation = getchar();
        getchar();
        if (operation < 48 || operation > 49) {
            printf("Invalid choice.\n");
        }
    }
    operation = operation - 48;
    //printf("Choice was:\t%d\n",operation);
    switch (operation)
    {
    case 0:
        //printf("0\n");
        system("systemctl status --no-pager dogpics");
        break;
    case 1:
        system("systemctl restart dogpics");
        break;
    default:
        break;
    }
}
```

<img id="image10" />

Since the command did not have an absolute path to the binary, it was easy for exploitation with a custom path. I created a binary named `/tmp/systemctl` that executes `/bin/bash`, added `/tmp` to the PATH variable, and successfully elevated my privileges.

<img id="image11" />

 ✅ Root Flag obtained.




<script>

// JSON object
const data = {
    "desc": "Exploit a recent code injection vulnerability to take over a website full of cute dog pictures!",
    "ip":  "10.10.46.35",
    "ports": "22/tcp,ssh,OpenSSH 8.0 (protocol 2.0);80/tcp,http,Golang net/http server (Go-IPFS json-rpc or InfluxDB API)",
    "difficulty":"medium",
    "id": "4"
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