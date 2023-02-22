
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
  ```sh linenums="1" hl_lines="6 10"
  
  ```

## <b>Enumeration</b>

## <b>Initial Access</b>

## <b>Privilege Escalation</b>

### <b>Gaining User access</b>

### <b>Gaining Root access</b>


<script>

// JSON object
const data = {
    "desc": "",
    "ip":  "",
    "ports": "",
    "difficulty":"easy",
    "id": "1"
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