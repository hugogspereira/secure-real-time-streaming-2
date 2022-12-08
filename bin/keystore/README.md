# Passwords

boxkeystore:     "omsqptaesd12345fommptvsnf54321iocmlesrfoqppms12345".

streamkeystore:  "12345omsqptaesd54321fommptvsnf12345iocmlesrfoqppms".

trustedstore:    "cIBXzKN5WU5aVMqYKuWGncATG35M3Yok6wJvZ0tdlnzBp0R1Gv".

# Steps:

keytool -genseckey -alias aeskey -keyalg AES -keysize 256 -storetype jceks -keystore boxstore.jks

...

keytool -genkey -alias rsakey -keyalg RSA -keystore boxstore.jks -keysize 2048 -storepass omsqptaesd12345fommptvsnf54321iocmlesrfoqppms12345

keytool -genkey -alias rsakey -keyalg RSA -keystore streamstore.jks -keysize 2048 -storepass 12345omsqptaesd54321fommptvsnf12345iocmlesrfoqppms

...

keytool -export -alias rsakey -keystore boxstore.jks -file box.cer

keytool -export -alias rsakey -keystore streamstore.jks -file stream.cer

...

keytool -exportcert -alias rsakey -keystore boxstore.jks -file boxbase64.cer -rfc

keytool -exportcert -alias rsakey -keystore streamstore.jks -file streambase64.cer -rfc

...

keytool -import -file box.cer -alias boxcert keystore trustedstore

keytool -import -file stream.cer -alias streamcert keystore trustedstore

...


keytool -list -v -keystore trustedstore