rm -rf ./.keys
mkdir ./.keys
openssl genrsa -out keypair.pem 4096
openssl rsa -in keypair.pem -pubout -out pub-key.pem
openssl pkcs8 -topk8 -inform PEM -outform PEM -in keypair.pem -out priv-key.pem -nocrypt
rm keypair.pem
mv priv-key.pem ./.keys
mv pub-key.pem ./.keys