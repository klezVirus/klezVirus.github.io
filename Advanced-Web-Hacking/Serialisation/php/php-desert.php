<?php

class RCE {

    public $cmd;
    
    function __construct($cmd){
        $this->cmd = $cmd;
    }

    function __wakeup(){
        shell_exec($this->cmd);
    }
}

class FileDelete{
    
    public $filename;
    
    function usefile(){
        // Do something
    }
    
    function __destruct(){
        unlink($this->filename);
    }
}

class Desert{
    public $name;
    
    function __construct($name){
        $this->name = $name;
        echo("[+] Constructing new desert!\n");
    }

    function __toString(){
        echo("[+] The desert is called: $this->name!\n");
        return $this->name;
    }

    function __wakeup(){
        echo("[+] New Desert created! Hello $this->name!\n");
    }

    function __destruct(){
        echo("[+] Bye Bye $this->name\n");
    }
    
}

$testfile = @fopen("test", "w+");
@fclose($testfile);

if($argc < 2){
    echo("[-] Not enough parameters");
}else if($argv[1] === "-d"){
    $desert = unserialize(file_get_contents("desert"));
}else if(($argv[1] === "-e") and ($argc > 2)){
    if($argv[2] === "desert"){
		file_put_contents("desert", serialize(new Desert("Sahara")));
	}else if($argv[2] === "rce"){
		file_put_contents("desert", serialize(new RCE("cmd /c calc")));
	}else if($argv[1] == "file-delete"){
		file_put_contents("desert", serialize(new FileDelete("test")));
	}
}
?>