rm -rf ./.keys
mkdir ./.keys
openssl ecparam -genkey -name prime256v1 -noout -out priv-key.pem
openssl ec -in priv-key.pem -pubout -out pub-key.pem
mv priv-key.pem ./.keys
mv pub-key.pem ./.keys