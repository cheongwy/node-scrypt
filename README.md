#### Introduction
node-scrypt is a node.js wrapper for the native C implementation of the scrypt encryption utility.

See http://www.tarsnap.com/scrypt.html for more details.

Build the native executables for your OS:
  git clone https://github.com/cheongwy/node-scrypt.git
  cd node-scrypt
  node-waf configure build
  

This should generate a number of binary files in build/default

Assemble the node-module:
  mkdir -p node-modules/node-scrypt/build
  cp build/default/scrypt.node node-modules/node-scrypt/build/
  cp build/default/scrypt_3.o node-modules/node-scrypt/build/
  cp scrypt.js node-modules/node-scrypt/
  cp package.json node-modules/node-scrypt/

Et voila now test it (todo)

