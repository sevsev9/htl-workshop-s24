openssl genrsa -out rsa/private.key 4096
openssl rsa -pubout -in rsa/private.key -out rsa/public.key