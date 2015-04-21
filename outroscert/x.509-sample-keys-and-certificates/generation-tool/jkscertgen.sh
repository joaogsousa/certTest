#!/bin/bash
#
# ----------------------------- jkscertgen 1.0 --------------------------------
#
# Note  : Check for latest version: http://www.swview.org/jkscertgen
#
# What  : A script to do all the following in one go
#           1) Generate four jks keystores (CA, service, client1, client2)
#           2) Self sign CA certificate with proper certificate extensions
#           3) CA certify service, client1, client2 certificates with proper
#              certificate extensions (AKI, SKI)
#           4) Add service certificate to client1, client2 keystores
#           5) Optionally, add client1 and client2 certificates to service
#              keystore. 
#
# Why   : Java provides 'keytool' to manage .jks keystores. However, it does
#         not provide CA (Certificate Authrority) capabilities. For someone
#         experimenting with public key encryption, this script can generate
#         all the keys and signed certificates based on a generated CA without
#         hassle.
#
#         Hope this will be a great 'learning script' as well.
#
# Version: 1.0
# Date   : 18th of June, 2008
# Licence: Creative Commons Attribution 3.0 (Add a fair attribution)
#
# Author : Kamal Wicramanayake
#          Software View - World Quality Trainings!
#          http://www.swview.org/
#
# Development environment:
#                          Fedora 7 (Linux)
#                          JDK 1.6.0_03
#                          openssl-0.9.8b
#
# Dependecies: OpenSSL
#
# Howto:
#        1) Copy this script to a new directory
#        2) Make sure the script is executable
#           $ chmod +x jkscertgen.sh
#        3) Execute
#           $ ./jkscertgen.sh
#
#
#        If everything went properly,
#
#        4) Customize this file according to your preferences (say by setting
#           your name as the CA,...).
#        5) Delete the old generated files and reexecute the script.
#
#
#
# IMPORTANT: This script internally executes key and certificate management
#            commands with passwords provided as command line arguments to them.
#            This is not recommended for a production environment. In a
#            production environment, you may simply omit the command line
#            password options and the commands will prompt you to enter the
#            passwords.
#
#            Other mechanisms exist to specify the passwords for openssl. See
#            the manual page of openssl for -passin and -passout options.
#
#            Importing trusted certificates to a a keystore is a security
#            sensitive operation. See the documentation of keytool for
#            guidelines to be used in a production environment like manually
#            checking the fingerprints.
#


# --- Edit the following to match with your preferences ---
# --- Default values also work fine ---


# Uncomment the following line if you plan to run this command multiple
# times so that all the files generated will be deleted before fresh files
# are generated.
#rm -f *.cer *.jks *.csr *.key *.p12 *.srl openssl.cnf *.pem


# Specify the key algorithm
KEYALG=RSA

# Add the generated client certificates to service keystore? [YES/NO]
ADD_CLIENT_TO_SERVICE=YES

# To slow down the process for you to see the steps, mention seconds
# to sleep after major steps. Specify 0 or a positive integer.
SLEEP=5

# CA Details
CA=swviewca
CA_DNAME="CN=Software View Certificate Authority, OU=Training, O=Software View, L=Colombo, S=Western, C=LK"
CA_KEYPASS=swviewcasecret
CA_KEYSTOREPASS=swviewcastoresecret
CA_VALIDITY=6000

# Test Service Details
SERVICE=myservice
SERVICE_DNAME="CN=My Test Service, OU=Training, O=Software View, L=Colombo, S=Western, C=LK"
SERVICE_KEYPASS=myservicesecret
SERVICE_KEYSTOREPASS=myservicestoresecret
SERVICE_VALIDITY=5500
CA_SERVICE_VALIDITY=5000


# Test Client 1 Details
CLIENT1=johnnie
CLIENT1_DNAME="CN=Johnnie Walker, OU=Training, O=Software View, L=Colombo, S=Western, C=LK"
CLIENT1_KEYPASS=johnniesecret
CLIENT1_KEYSTOREPASS=johnniestoresecret
CLIENT1_VALIDITY=5500
CA_CLIENT1_VALIDITY=5000

# Test Client 2 Details
CLIENT2=jack
CLIENT2_DNAME="CN=Jack Daniel, OU=Training, O=Software View, L=Colombo, S=Western, C=LK"
CLIENT2_KEYPASS=jacksecret
CLIENT2_KEYSTOREPASS=jackstoresecret
CLIENT2_VALIDITY=5500
CA_CLIENT2_VALIDITY=5000



# --- You need not edit what follows ---


# Check if keytool and openssl commands exist
if ! which keytool >/dev/null 2> /dev/null; then
    echo "keytool command cannot be found. Haven't you installed Java (JDK)?"
    exit 1
fi

if ! which openssl >/dev/null 2> /dev/null; then
    echo "openssl command cannot be found. Haven't you installed OpenSSL?"
    exit 2
fi


# See http://www.openssl.org/docs/apps/x509v3_config.html
# for the content of the following openssl.cnf file.

# Consult pp 36, 26, 27 of http://www.ietf.org/rfc/rfc3280.txt for the
# meanings of basicConstraints, subjectKeyIdentifier, authorityKeyIdentifier in
# X.509 certificates
echo Writing an openssl.cnf file
cat > openssl.cnf << EOF

[ v3_ca ]
basicConstraints = CA:true
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always


[ v3_usr ]
basicConstraints = CA:false
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
nsComment = "OpenSSL Generated Certificate"

EOF


echo "Generating CA keys"
keytool -genkeypair -keyalg $KEYALG -alias $CA -keypass $CA_KEYPASS -dname "$CA_DNAME" -keystore $CA.jks -storepass $CA_KEYSTOREPASS -validity $CA_VALIDITY

echo "Generate CA certificate sign request"
keytool -certreq -alias $CA -keypass $CA_KEYPASS -file $CA.csr -keystore $CA.jks -storepass $CA_KEYSTOREPASS

echo "Exporting CA private key, certificate to PKCS12 store"
echo -e "\nMove the mouse here and there to make the following process faster.......!\n"
# FUN: -destkeypass is not really required. However, if you don't specify it,
# something goes wrong. Hence, retain it. keytool will warn you. But
# the operation will complete properly.
keytool -importkeystore -srckeystore $CA.jks -destkeystore $CA.p12 -srcstoretype JKS -deststoretype PKCS12 -srcstorepass $CA_KEYSTOREPASS -deststorepass $CA_KEYSTOREPASS -srcalias $CA -destalias $CA -srckeypass $CA_KEYPASS -destkeypass $CA_KEYPASS -noprompt

echo "Convert pkcs12 to pem"
openssl pkcs12 -in $CA.p12 -out $CA.pem -passin pass:$CA_KEYSTOREPASS -passout pass:$CA_KEYSTOREPASS

echo "Adding general CA extensions to CA certificate and self sign"
openssl x509 -req -days $CA_VALIDITY -in $CA.csr -signkey $CA.pem -CAcreateserial -out $CA.cer -passin pass:$CA_KEYSTOREPASS -extfile openssl.cnf -extensions v3_ca


echo "Importing CA self signed certificate with extensions to CA keystore"
keytool -importcert -alias $CA -file $CA.cer -keystore $CA.jks -storepass $CA_KEYSTOREPASS -keypass $CA_KEYPASS


# Get a pem again with the updated certificate from CA keystore
# Wouldn't it be possible/easier to replace the old certificate with the new
# certificate in .pem file?
rm -f $CA.p12 $CA.pem

echo -e "\nMove the mouse again.......!\n"
keytool -importkeystore -srckeystore $CA.jks -destkeystore $CA.p12 -srcstoretype JKS -deststoretype PKCS12 -srcstorepass $CA_KEYSTOREPASS -deststorepass $CA_KEYSTOREPASS -srcalias $CA -destalias $CA -srckeypass $CA_KEYPASS -destkeypass $CA_KEYPASS -noprompt

openssl pkcs12 -in $CA.p12 -out $CA.pem -passin pass:$CA_KEYSTOREPASS -passout pass:$CA_KEYSTOREPASS




echo ""
echo "CA Keys And Self Signed Certificate Generation Complete"
echo "About to generate [$SERVICE] keys/certificates..."
sleep $SLEEP

# Step 2: Create keys for $SERVICE

echo "Generate $SERVICE keys"
keytool -genkeypair -keyalg $KEYALG -alias $SERVICE -keypass $SERVICE_KEYPASS -dname "$SERVICE_DNAME" -keystore $SERVICE.jks -storepass $SERVICE_KEYSTOREPASS -validity $SERVICE_VALIDITY

echo "Generating $SERVICE csr"
keytool -certreq -alias $SERVICE -keypass $SERVICE_KEYPASS -file $SERVICE.csr -keystore $SERVICE.jks -storepass $SERVICE_KEYSTOREPASS

echo "CA signs $SERVICE certificate"
openssl x509 -req -days $CA_SERVICE_VALIDITY -in $SERVICE.csr -CA $CA.pem -CAcreateserial -out $SERVICE.cer -passin pass:$CA_KEYSTOREPASS -extfile openssl.cnf -extensions v3_usr

echo "Import CA trusted certificated to $SERVICE keystore"
keytool -importcert -alias $CA -file $CA.cer -keystore $SERVICE.jks -storepass $SERVICE_KEYSTOREPASS -noprompt

echo "Import CA signed $SERVICE certificate to $SERVICE keystore"
keytool -importcert -alias $SERVICE -file $SERVICE.cer -keystore $SERVICE.jks -storepass $SERVICE_KEYSTOREPASS -keypass $SERVICE_KEYPASS




echo ""
echo "[$SERVICE] Keys and Certificate Generation Complete"
echo "About to generate [$CLIENT1] keys/certificates..."
sleep $SLEEP

keytool -genkeypair -keyalg $KEYALG -alias $CLIENT1 -keypass $CLIENT1_KEYPASS -dname "$CLIENT1_DNAME" -keystore $CLIENT1.jks -storepass $CLIENT1_KEYSTOREPASS -validity $CLIENT1_VALIDITY

keytool -certreq -alias $CLIENT1 -keypass $CLIENT1_KEYPASS -file $CLIENT1.csr -keystore $CLIENT1.jks -storepass $CLIENT1_KEYSTOREPASS

openssl x509 -req -days $CA_CLIENT1_VALIDITY -in $CLIENT1.csr -CA $CA.pem -CAserial $CA.srl -out $CLIENT1.cer -passin pass:$CA_KEYSTOREPASS -extfile openssl.cnf -extensions v3_usr

keytool -importcert -alias $CA -file $CA.cer -keystore $CLIENT1.jks -storepass $CLIENT1_KEYSTOREPASS -noprompt

keytool -importcert -alias $CLIENT1 -file $CLIENT1.cer -keystore $CLIENT1.jks -storepass $CLIENT1_KEYSTOREPASS -keypass $CLIENT1_KEYPASS

# Get the CA signed $SERVICE certificated imported to $CLIENT1 store
keytool -importcert -alias $SERVICE -file $SERVICE.cer -keystore $CLIENT1.jks -storepass $CLIENT1_KEYSTOREPASS




echo ""
echo "[$CLIENT1] Keys and Certificate Generation Complete"
echo "About to generate [$CLIENT2] keys/certificates..."
sleep $SLEEP

keytool -genkeypair -keyalg $KEYALG -alias $CLIENT2 -keypass $CLIENT2_KEYPASS -dname "$CLIENT2_DNAME" -keystore $CLIENT2.jks -storepass $CLIENT2_KEYSTOREPASS -validity $CLIENT2_VALIDITY

keytool -certreq -alias $CLIENT2 -keypass $CLIENT2_KEYPASS -file $CLIENT2.csr -keystore $CLIENT2.jks -storepass $CLIENT2_KEYSTOREPASS

openssl x509 -req -days $CA_CLIENT2_VALIDITY -in $CLIENT2.csr -CA $CA.pem -CAserial $CA.srl -out $CLIENT2.cer -passin pass:$CA_KEYSTOREPASS -extfile openssl.cnf -extensions v3_usr

keytool -importcert -alias $CA -file $CA.cer -keystore $CLIENT2.jks -storepass $CLIENT2_KEYSTOREPASS -noprompt

keytool -importcert -alias $CLIENT2 -file $CLIENT2.cer -keystore $CLIENT2.jks -storepass $CLIENT2_KEYSTOREPASS -keypass $CLIENT2_KEYPASS

# Get the CA signed $SERVICE certificated imported to $CLIENT2 store
keytool -importcert -alias $SERVICE -file $SERVICE.cer -keystore $CLIENT2.jks -storepass $CLIENT2_KEYSTOREPASS




echo ""
echo "[$CLIENT2] Keys and Certificate Generation Complete"

if [ "$ADD_CLIENT_TO_SERVICE" == "YES" ]; then
    echo "About to add client certificates to server keystore"
    sleep $SLEEP

    keytool -importcert -alias $CLIENT1 -file $CLIENT1.cer -keystore $SERVICE.jks -storepass $SERVICE_KEYSTOREPASS

    keytool -importcert -alias $CLIENT2 -file $CLIENT2.cer -keystore $SERVICE.jks -storepass $SERVICE_KEYSTOREPASS
fi

echo -e "\n\nYou will retain all .jks files. If you plan to sign more certificates with $CA, you may wish to retain $CA.pem and $CA.srl. $CA.pem contains the $CA's private key and self signed certificate. $CA.srl contains a serial key that increments automatically and goes into each certificate signed. Other files can be deleted and regenerated from .jks files if required." 

echo -e "\nYou may verify the results with the following commands with correct values for the file and password:"
echo "    $ keytool -list -keystore file.jks -storepass password"
echo "    $ keytool -v -list -keystore file.jks -storepass password | less"
echo "    $ keytool -printcert -file file.cer"
echo "    $ cat file.pem"
