var scrypt = require('./build/default/scrypt');

exports.encrypt = scrypt.encrypt;

//var enc = scrypt.encrypt("golden");
//console.log("Run "+enc);