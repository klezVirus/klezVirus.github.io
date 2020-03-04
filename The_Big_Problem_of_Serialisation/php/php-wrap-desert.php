<?php
error_reporting(0);
// Requiring Slim 3.8.1 to enable visibility over POP gadgets
// php composer.phar yii/yii:1.1.20
// php composer.phar require slim/slim:3.8.1
// php composer.phar require guzzlehttp/guzzle:6.0.1 (re-unpatched version)
require 'vendor/autoload.php';

// Function vulnerable to phar:// deserialization
function vulnerable_to_phar($filename){
	echo("[*] Open file: $filename"); 
	$content = file_get_contents($filename);
	print($content);
}

// Function vulnerable to RCE via insecure deserialization
function vulnerable_to_rce_via_gadgets($filename){
	echo("[*] Deserializing: $filename"); 
	$desert = unserialize(file_get_contents($filename));
	print($desert);
}
// Getting args from stdin
$args = getopt("f:p");
$file = $args["f"] or die("[-] Filename is required");

// Executing vulnerable functions
if(is_bool($args["p"])){
	vulnerable_to_phar($file);
}else{
	vulnerable_to_rce_via_gadgets($file);
}
?>
