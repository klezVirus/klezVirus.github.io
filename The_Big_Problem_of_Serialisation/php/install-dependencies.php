<?php
// Install deèendencies
system("php composer.phar require yii/yii:1.1.20");
system("php composer.phar require slim/slim:3.8.1");
system("php composer.phar require guzzlehttp/guzzle:6.0.0");

// Patching Guzzle for PHAR deserialization
$content = file_get_contents("./vendor/guzzlehttp/psr7/src/FnStream.php");
$new_content = preg_replace("/__wakeup/", "screwed_up", $content);
file_put_contents("./vendor/guzzlehttp/psr7/src/FnStream.php", $new_content);

?>