#!/bin/bash

systemctl start nvm_daemon
export MODULE_PKCS11=/usr/lib/libsmw_pkcs11.so.5
pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --keypairgen \
            --key-type rsa:2048 \
            --id 02 \
            --label "MyRSAKey" \
            --usage-sign \
            --allowed-mechanisms "SHA256-RSA-PKCS-PSS"
pkcs11-tool --module $MODULE_PKCS11 \
    --login \
    --read-object --type pubkey \
    --id 02 \
    --output-file rsa2k_public_key.der
dd if=/dev/urandom of=data_test.bin bs=1 count=64

pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --sign \
            --id 02 \
            --mechanism SHA256-RSA-PKCS-PSS \
            --input-file data_test.bin \
            --output-file signature.bin
openssl rsa -pubin -inform DER -in rsa2k_public_key.der -outform PEM -out rsa2k_public_key.pem
openssl dgst -sha256 -verify rsa2k_public_key.pem -signature signature.bin \
    -sigopt rsa_padding_mode:pss \
    -sigopt rsa_pss_saltlen:32 \
    data_test.bin

timeout 5 ./ele_rsa_app -S -i data_test.bin -o signature.bin -I 02 -P 111

openssl dgst -sha256 -verify rsa2k_public_key.pem -signature signature.bin \
    -sigopt rsa_padding_mode:pss \
    -sigopt rsa_pss_saltlen:32 \
    data_test.bin

# === Positive test: verify app's signature with app ===
echo "--- Test: Verify with app (positive) ---"
./ele_rsa_app -V -i data_test.bin -s signature.bin -I 02 -P 111 -q
if [ $? -ne 0 ]; then
    echo "FAIL: App verification of app signature failed!"
    exit 1
fi
echo "PASS: App verification OK"

# === Negative test: corrupt data should fail verification ===
echo "--- Test: Verify with corrupted data (negative) ---"
cp data_test.bin data_test_corrupt.bin
echo "X" >> data_test_corrupt.bin
./ele_rsa_app -V -i data_test_corrupt.bin -s signature.bin -I 02 -P 111 -q
if [ $? -eq 0 ]; then
    echo "FAIL: App verification should have failed with corrupted data!"
    exit 1
fi
echo "PASS: Corrupted data correctly rejected"
rm -f data_test_corrupt.bin

# === Cross-verify: pkcs11-tool signature verified by app ===
echo "--- Test: Cross-verify pkcs11-tool signature with app ---"
pkcs11-tool --module $MODULE_PKCS11 \
    --login \
    --sign \
    --id 02 \
    --mechanism SHA256-RSA-PKCS-PSS \
    --input-file data_test.bin \
    --output-file signature_tool.bin

./ele_rsa_app -V -i data_test.bin -s signature_tool.bin -I 02 -P 111 -q
if [ $? -ne 0 ]; then
    echo "FAIL: App verification of pkcs11-tool signature failed!"
    exit 1
fi
echo "PASS: Cross-verification OK"
rm -f signature_tool.bin

pkcs11-tool --module $MODULE_PKCS11 \
    --login \
    --delete-object \
    --id 02 \
    --type privkey
systemctl stop nvm_daemon
rm -rf /etc/ele/ data_test.bin rsa2k_public_key.der rsa2k_public_key.pem signature.bin /usr/share/smw/smw_objects_database.dat