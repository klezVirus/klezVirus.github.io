var argv = require('yargs')
	.usage('Usage: $0 -c [cmd]')
	.alias('c','command')
    .demandOption(['c'])
    .argv;

var p = argv.command.toString();


var x = new Array();
for(var i=0; i < p.length; i++){
	x.push(p.charCodeAt(i));
}
p = "String.fromCharCode([" + x.toString() + "])";
console.log(p);			