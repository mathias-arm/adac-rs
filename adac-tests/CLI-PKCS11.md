# PKCS#11 CLI Tests

## Setup

Tests require `openssl`, `softhsm2` and `pkcs11-tool` (the latter is part of
the `opensc` package).

On Linux, the location of the token state for non-root users needs to be
configured, use the following instructions (and update `.profile` or shell
configuration to set the value of `SOFTHSM2_CONF` for future sessions):
```
$ mkdir -p $HOME/local/lib/softhsm/tokens
$ echo "directories.tokendir = $HOME/local/lib/softhsm/tokens" \
    > $HOME/local/lib/softhsm/softhsm2.conf
$ export SOFTHSM2_CONF=$HOME/local/lib/softhsm/softhsm2.conf
```

Initialize softhsm2 token.
```
$ softhsm2-util --init-token --free --label "test-token" --pin 1234 --so-pin 4321
```

## ECDSA P-384 Tests

```
$ for i in adac-tests/resources/keys/EcdsaP384Key-*.pk8 ; do \
    openssl pkey -in $i -outform der -out private.der ; \
    openssl pkey -in $i -pubout -outform der -out public.der ; \
    openssl pkey -in $i -pubout -out $(basename $i .pk8).pub ; \
    KEYID=$(sha256sum public.der | cut -d \  -f 1) ; \
    echo $KEYID ; \
    pkcs11-tool --module /opt/homebrew/lib/softhsm/libsofthsm2.so --pin 1234 \
      --write-object private.der --type privkey --id $KEYID --label $KEYID ; \
    pkcs11-tool --module /opt/homebrew/lib/softhsm/libsofthsm2.so --pin 1234 \
      --write-object public.der --type pubkey --id $KEYID --label $KEYID ; \
    rm private.der public.der ; \
done
```

### Sign Root CA certificate

```
$ cargo run -p adac-cli -- sign -c adac-tests/test-config.toml \
    -k b1ac929e1db189bcc276f40f415365986356419933659b1952f7b5b5191a4656 \
    -r EcdsaP384Key-0.pub -s root -o root.crt
```

### Sign Intermediate CA certificate

```
$ cargo run -p adac-cli -- sign -c adac-tests/test-config.toml \
    -k b1ac929e1db189bcc276f40f415365986356419933659b1952f7b5b5191a4656 \
    -r EcdsaP384Key-1.pub -s intermediate -i root.crt -o inter.crt
```

### Sign Test 1 certificate

```
$ cargo run -p adac-cli -- sign -c adac-tests/test-config.toml \
    -k 83c7d7d324b2ad2d25b554f3f11d3452a93cb12e10fe24a0f487c07a0b737ecc \
    -r EcdsaP384Key-2.pub -i inter.crt -s crt1 -o crt1.crt
$ cargo run -p adac-cli -- verify -p crt1.crt
```

### Sign Test 2 certificate

```
$ cargo run -p adac-cli -- sign -c adac-tests/test-config.toml \
    -k 83c7d7d324b2ad2d25b554f3f11d3452a93cb12e10fe24a0f487c07a0b737ecc \
    -r EcdsaP384Key-2.pub -i inter.crt -s crt2 -o crt2.crt
$ cargo run -p adac-cli -- verify -p crt2.crt
```

### Sign Test 3 certificate

```
$ cargo run -p adac-cli -- sign -c adac-tests/test-config.toml \
    -k 83c7d7d324b2ad2d25b554f3f11d3452a93cb12e10fe24a0f487c07a0b737ecc \
    -r EcdsaP384Key-2.pub -i inter.crt -s crt3 -o crt3.crt
$ cargo run -p adac-cli -- verify -p crt3.crt
```

## Tests using NSS PKCS#11 module

Create token database:
```
rm -rf tmp ; mkdir -p tmp
export NSS_LIB_DIRECTORY=$PWD/tmp
export NSS_LIB_PARAMS=configDir=$NSS_LIB_DIRECTORY
echo 1234 > $NSS_LIB_DIRECTORY/pin.txt
certutil -N -d $NSS_LIB_DIRECTORY -f $NSS_LIB_DIRECTORY/pin.txt
```

Run test program:
```
cargo run --bin adac_pkcs11_test check \
    --module /opt/homebrew/lib/libsoftokn3.dylib \
    --pin 1234 --label "NSS Certificate DB"

cargo run --bin adac_pkcs11_test test \
    --module /opt/homebrew/lib/libsoftokn3.dylib \
    --pin 1234 --label "NSS Certificate DB"
```
