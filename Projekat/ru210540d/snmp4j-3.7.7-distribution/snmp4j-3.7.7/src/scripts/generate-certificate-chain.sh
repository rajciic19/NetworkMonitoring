#!/bin/bash

KEYPASS=snmp4j
STOREPASS=snmp4j
KEYSIZE=4096
VALIDITY=100000
ROOT_DNAME="CN=root,OU=snmp4j-unit-test,O=AGENTPP,L=Stuttgart,S=Baden-Wuerttemberg,C=DE"
CA_DNAME="CN=ca,OU=snmp4j-unit-test,O=AGENTPP,L=Stuttgart,S=Baden-Wuerttemberg,C=DE"
SANEXT="san=dns:localhost,ip:127.0.0.1"
CERT_ALIAS_SERVER=snmp4j-agent
CERT_ALIAS_CLIENT=snmp4j-manager
CERT_DNAME_SERVER="CN=server,OU=snmp4j-unit-test,O=AGENTPP,L=Stuttgart,S=Baden-Wuerttemberg,C=DE"
CERT_DNAME_CLIENT="CN=client,OU=snmp4j-unit-test,O=AGENTPP,L=Stuttgart,S=Baden-Wuerttemberg,C=DE"
KEYSTORE=agent-keystore.jks
PKCS12_KEYSTORE=agent-keystore.p12
TRUSTSTORE=agent-truststore.jks
KEYSTORE_CLIENT=client-keystore.jks
TRUSTSTORE_CLIENT=client-truststore.jks
OPENSSL_CONFIG=openssl-revoke-config.cnf

if [ $# -gt 0 ]; then
  OPENSSL_CONFIG=$1
  echo "Using openssl certificate revocation config from $OPENSSL_CONFIG"
fi

echo "===================================================="
echo "Deleting existing keystores: ca.jks root.jks $KEYSTORE $TRUSTSTORE $KEYSTORE_CLIENT $TRUSTSTORE_CLIENT $PKCS12_KEYSTORE"
echo "Deleting existing certs: ca.pem root.pem server.pem ca-key.pem client.pem crl_server.pem"
echo "Deleting existing openssl CA database and CRL number files: ca_crl_index.txt ca_crl_number"
echo "===================================================="

rm ca.jks root.jks $KEYSTORE $TRUSTSTORE $KEYSTORE_CLIENT $TRUSTSTORE_CLIENT 2> /dev/null
rm ca.pem root.pem server.pem ca-key.pem client.pem crl_server.pem 2> /dev/null
rm $PKCS12_KEYSTORE 2> /dev/null
rm ca_crl_index.txt ca_crl_index.txt.old ca_crl_index.txt.attr.old ca_crl_number ca_crl_number.old 2> /dev/null

ls

echo "===================================================="
echo "Creating test chain root -> ca"
echo "===================================================="

# generate private keys (for root and ca)
keytool -genkeypair -alias root -dname $ROOT_DNAME -validity $VALIDITY -keyalg RSA -keysize $KEYSIZE -ext bc:c -keystore root.jks -keypass $KEYPASS -storepass $STOREPASS
keytool -genkeypair -alias ca -dname $CA_DNAME -validity $VALIDITY -keyalg RSA -keysize $KEYSIZE -ext bc:c -keystore ca.jks -keypass $KEYPASS -storepass $STOREPASS

# generate root certificate

keytool -exportcert -rfc -keystore root.jks -alias root -storepass snmp4j > root.pem

# generate a certificate for ca signed by root (root -> ca)

keytool -keystore ca.jks -storepass $STOREPASS -certreq -alias ca \
| keytool -keystore root.jks -storepass $STOREPASS -gencert -alias root -ext bc=0 -ext san=dns:ca -rfc > ca.pem

# import ca cert chain into ca.jks

keytool -keystore ca.jks -storepass $STOREPASS -importcert -trustcacerts -noprompt -alias root -file root.pem
keytool -keystore ca.jks -storepass $STOREPASS -importcert -alias ca -file ca.pem

echo  "===================================================================="
echo  "Test CA and root chain generated. Now generating agent.jks ..."
echo  "===================================================================="

# generate private keys (for server and client)
keytool -genkeypair -alias $CERT_ALIAS_SERVER -dname $CERT_DNAME_SERVER -validity $VALIDITY -keyalg RSA -keysize $KEYSIZE -keystore $KEYSTORE -keypass $KEYPASS -storepass $STOREPASS
keytool -genkeypair -alias $CERT_ALIAS_CLIENT -dname $CERT_DNAME_CLIENT -validity $VALIDITY -keyalg RSA -keysize $KEYSIZE -keystore $KEYSTORE_CLIENT -keypass $KEYPASS -storepass $STOREPASS

# generate a certificate for server and client signed by ca (root -> ca -> server)

keytool -keystore $KEYSTORE -storepass $STOREPASS -certreq -alias $CERT_ALIAS_SERVER \
| keytool -keystore ca.jks -storepass $STOREPASS -gencert -alias ca -ext ku:c=dig,keyEnc -ext $SANEXT -ext eku=sa,ca -rfc > server.pem
keytool -keystore $KEYSTORE_CLIENT -storepass $STOREPASS -certreq -alias $CERT_ALIAS_CLIENT \
| keytool -keystore ca.jks -storepass $STOREPASS -gencert -alias ca -ext ku:c=dig,keyEnc -ext $SANEXT -ext eku=sa,ca -rfc > client.pem

# export ca.key to pk12 format for openssl
keytool -importkeystore -srckeystore ca.jks -srcstorepass $STOREPASS -srckeypass $KEYPASS -destkeystore $PKCS12_KEYSTORE -deststoretype PKCS12 -srcalias ca -deststorepass $STOREPASS -destkeypass $KEYPASS -noprompt
openssl pkcs12 -in $PKCS12_KEYSTORE -password pass:$KEYPASS -nodes -nocerts -out ca-key.pem

# import server cert chain into $KEYSTORE
keytool -keystore $KEYSTORE -storepass $STOREPASS -importcert -trustcacerts -noprompt -alias root -file root.pem
keytool -keystore $KEYSTORE -storepass $STOREPASS -importcert -alias ca -file ca.pem
keytool -keystore $KEYSTORE -storepass $STOREPASS -importcert -alias $CERT_ALIAS_SERVER -file server.pem
keytool -keystore $KEYSTORE_CLIENT -storepass $STOREPASS -importcert -trustcacerts -noprompt -alias root -file root.pem
keytool -keystore $KEYSTORE_CLIENT -storepass $STOREPASS -importcert -alias ca -file ca.pem
keytool -keystore $KEYSTORE_CLIENT -storepass $STOREPASS -importcert -alias $CERT_ALIAS_CLIENT -file client.pem

echo "=================================================="
echo "Keystore generated. Now generating truststores ..."
echo "=================================================="

# import server cert chain into $TRUSTSTORE
keytool -keystore $TRUSTSTORE -storepass $STOREPASS -importcert -trustcacerts -noprompt -alias root -file root.pem
keytool -keystore $TRUSTSTORE -storepass $STOREPASS -importcert -alias ca -file ca.pem
keytool -keystore $TRUSTSTORE -storepass $STOREPASS -importcert -alias $CERT_ALIAS_SERVER -file server.pem
keytool -keystore $TRUSTSTORE_CLIENT -storepass $STOREPASS -importcert -trustcacerts -noprompt -alias root -file root.pem
keytool -keystore $TRUSTSTORE_CLIENT -storepass $STOREPASS -importcert -alias ca -file ca.pem
keytool -keystore $TRUSTSTORE_CLIENT -storepass $STOREPASS -importcert -alias $CERT_ALIAS_CLIENT -file client.pem

touch ca_crl_index.txt
echo "00" > ca_crl_number
openssl ca -revoke server.pem -keyfile ca-key.pem -cert ca.pem -config $OPENSSL_CONFIG
openssl ca -gencrl -keyfile ca-key.pem -cert ca.pem -out crl_server.pem -config $OPENSSL_CONFIG
