var scrypt = require('./build/default/scrypt');

var enc = scrypt.encrypt("golden");
console.log("Run "+new Buffer(enc,encoding='base64').toString('utf8'));