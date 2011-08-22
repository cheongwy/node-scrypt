var scrypt = require('./build/default/scrypt');

var encrypt = function(password) {
	var hash = scrypt.encrypt(password);
	return hash;
};

for(var i =0; i< 12; i++) {
	var enc = encrypt("golden");
	console.log("Hash=> "+enc);
	console.log("Length=> "+enc.length);
	
	if(enc !== "I8OYrbL8BeW677adEoJlBqiRuygRwFxobkpSFGdXvxs=") {
		throw Error("Hash mismatch");
	}
	
}

exports.encrypt = encrypt; 
