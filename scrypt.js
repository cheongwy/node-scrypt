var scrypt = require('./build/default/scrypt');

var encrypt = function(password) {
	var hash = scrypt.encrypt(password);
	return new Buffer(hash, 'base64').toString('base64');
};

//for(var i =0; i< 10; i++) {
//	var enc = encrypt("golden");
//	console.log("Hash=> "+enc);
//	console.log("Length=> "+enc.length);
//}

exports.encrypt = encrypt; 
