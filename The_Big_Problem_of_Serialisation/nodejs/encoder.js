var fs = require('fs')
var argv = require('yargs')
	.usage('Usage: $0 -f file')
	.alias('f','file')
    .demandOption(['f'])
    .argv;

function encode(data){
	var x = new Array();
	for(var i=0; i < data.length; i++){
		x.push(data.charCodeAt(i));
	}
	var encoded_data = "String.fromCharCode([" + x.toString() + "])";
	console.log(encoded_data);
	return encoded_data;
}

fs.readFile(argv.file, function(err, data) {
	if (err) throw err;
	var payload = JSON.parse(data);
	payload["rce"] = encode(payload["rce"]);
	console.log(payload);
	});