generate private and public key in pem
openssl rsa -in private-key.pem -pubout -out public-key.pem 

generate private key in pem and public key in der
openssl rsa -in private-key.pem -pubout -outform der -out public-key.der

public key pem to der: 
openssl rsa -pubin -in public-key.pem -outform der -out public-key.der

sign data file with private key and output binary file:
openssl dgst -sha256 -sign private-key.pem asia-androidx-liveness.txt > livenesslicense.bin

try changing the content of asia_androidx_liveness.txt under raw folder. This would return is Valid  = false
