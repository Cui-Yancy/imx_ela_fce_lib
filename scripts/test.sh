#!/bin/bash

# ============================================================
# Phase 1: Setup — start daemon, generate RSA key, test data
# ============================================================
echo ""
echo "========================================"
echo "  Phase 1: Environment Setup"
echo "========================================"
echo ""

systemctl start nvm_daemon
echo "[OK] nvm_daemon started"

export MODULE_PKCS11=/usr/lib/libsmw_pkcs11.so.5

pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --keypairgen \
            --key-type rsa:2048 \
            --id 02 \
            --label "MyRSAKey" \
            --usage-sign \
            --allowed-mechanisms "SHA256-RSA-PKCS-PSS"
echo "[OK] RSA 2048 key pair generated (id=02)"

pkcs11-tool --module $MODULE_PKCS11 \
    --login \
    --read-object --type pubkey \
    --id 02 \
    --output-file rsa2k_public_key.der
echo "[OK] Public key exported (rsa2k_public_key.der)"

dd if=/dev/urandom of=data_test.bin bs=1M count=2
echo "[OK] Test data generated (data_test.bin, 2 MB)"

# ============================================================
# Phase 2: pkcs11-tool sign + OpenSSL verify (baseline)
# ============================================================
echo ""
echo "========================================"
echo "  Phase 2: pkcs11-tool Sign + OpenSSL Verify"
echo "========================================"
echo ""

pkcs11-tool --module $MODULE_PKCS11 \
            --login \
            --sign \
            --id 02 \
            --mechanism SHA256-RSA-PKCS-PSS \
            --input-file data_test.bin \
            --output-file signature.bin
echo "[OK] pkcs11-tool signing done"

openssl rsa -pubin -inform DER -in rsa2k_public_key.der -outform PEM -out rsa2k_public_key.pem

openssl dgst -sha256 -verify rsa2k_public_key.pem -signature signature.bin \
    -sigopt rsa_padding_mode:pss \
    -sigopt rsa_pss_saltlen:32 \
    data_test.bin
if [ $? -eq 0 ]; then
    echo "[PASS] OpenSSL verification of pkcs11-tool signature OK"
else
    echo "[FAIL] OpenSSL verification of pkcs11-tool signature failed!"
    exit 1
fi

# ============================================================
# Phase 3: App sign + OpenSSL verify
# ============================================================
echo ""
echo "========================================"
echo "  Phase 3: ELE App Sign + OpenSSL Verify"
echo "========================================"
echo ""

echo "--- Running: ele_rsa_app sign ---"
./ele_rsa_app -S -i data_test.bin -o signature.bin -I 02 -P 111
echo "[OK] App signing done"

openssl dgst -sha256 -verify rsa2k_public_key.pem -signature signature.bin \
    -sigopt rsa_padding_mode:pss \
    -sigopt rsa_pss_saltlen:32 \
    data_test.bin
if [ $? -eq 0 ]; then
    echo "[PASS] OpenSSL verification of app signature OK"
else
    echo "[FAIL] OpenSSL verification of app signature failed!"
    exit 1
fi

# ============================================================
# Phase 4: App verify (positive)
# ============================================================
echo ""
echo "========================================"
echo "  Phase 4: ELE App Verify — Positive Test"
echo "========================================"
echo ""

./ele_rsa_app -V -i data_test.bin -s signature.bin -I 02 -P 111 -q
if [ $? -ne 0 ]; then
    echo "[FAIL] App verification of app signature failed!"
    exit 1
fi
echo "[PASS] App verification of app signature OK"

# ============================================================
# Phase 5: App verify with corrupted data (negative)
# ============================================================
echo ""
echo "========================================"
echo "  Phase 5: ELE App Verify — Negative Test"
echo "         (corrupted data should be rejected)"
echo "========================================"
echo ""

cp data_test.bin data_test_corrupt.bin
echo "X" >> data_test_corrupt.bin
echo "[INFO] Corrupted data created (data_test_corrupt.bin)"

./ele_rsa_app -V -i data_test_corrupt.bin -s signature.bin -I 02 -P 111 -q
if [ $? -eq 0 ]; then
    echo "[FAIL] App verification should have failed with corrupted data!"
    exit 1
fi
echo "[PASS] Corrupted data correctly rejected"
rm -f data_test_corrupt.bin

# ============================================================
# Phase 6: Cross-verify — pkcs11-tool signature verified by app
# ============================================================
echo ""
echo "========================================"
echo "  Phase 6: Cross-Verify"
echo "    pkcs11-tool sign → ELE App verify"
echo "========================================"
echo ""

pkcs11-tool --module $MODULE_PKCS11 \
    --login \
    --sign \
    --id 02 \
    --mechanism SHA256-RSA-PKCS-PSS \
    --input-file data_test.bin \
    --output-file signature_tool.bin
echo "[OK] pkcs11-tool signing done (signature_tool.bin)"

./ele_rsa_app -V -i data_test.bin -s signature_tool.bin -I 02 -P 111 -q
if [ $? -ne 0 ]; then
    echo "[FAIL] App verification of pkcs11-tool signature failed!"
    exit 1
fi
echo "[PASS] Cross-verification: pkcs11-tool ↔ ELE App signature OK"
rm -f signature_tool.bin

# ============================================================
# Phase 7: Cleanup
# ============================================================
echo ""
echo "========================================"
echo "  Phase 7: Cleanup"
echo "========================================"
echo ""

pkcs11-tool --module $MODULE_PKCS11 \
    --login \
    --delete-object \
    --id 02 \
    --type privkey
echo "[OK] RSA key deleted from token"

systemctl stop nvm_daemon
echo "[OK] nvm_daemon stopped"

rm -rf /etc/ele/ data_test.bin rsa2k_public_key.der rsa2k_public_key.pem signature.bin /usr/share/smw/smw_objects_database.dat
echo "[OK] Temporary files cleaned up"

echo ""
echo "========================================"
echo "  All tests completed successfully!"
echo "========================================"
echo ""