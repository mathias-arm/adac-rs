# adac-cli test

## Extract public keys

```
openssl pkey -in resources/keys/EcdsaP384Key-0.pk8 -pubout -out EcdsaP384Key-0.pub
openssl pkey -in resources/keys/EcdsaP384Key-1.pk8 -pubout -out EcdsaP384Key-1.pub
openssl pkey -in resources/keys/EcdsaP384Key-2.pk8 -pubout -out EcdsaP384Key-2.pub
```

## Tests

### Sign Root CA certificate

```
../target/release/adac-cli sign -c test-config.toml \
    -p resources/keys/EcdsaP384Key-0.pk8 -r EcdsaP384Key-0.pub \
    -s root -o root.crt
```

### Sign Intermediate CA certificate

```
../target/release/adac-cli sign -c test-config.toml \
    -p resources/keys/EcdsaP384Key-0.pk8 -r EcdsaP384Key-1.pub \
    -s intermediate -i root.crt -o inter.crt
```

### Sign Test 1 certificate

```
../target/release/adac-cli sign -c test-config.toml \
    -p resources/keys/EcdsaP384Key-1.pk8 -r EcdsaP384Key-2.pub \
    -i inter.crt -s crt1 -o crt1.crt

../target/release/adac-cli verify -p crt1.crt
```

### Sign Test 2 certificate

```
../target/release/adac-cli sign -c test-config.toml \
    -p resources/keys/EcdsaP384Key-1.pk8 -r EcdsaP384Key-2.pub \
    -i inter.crt -s crt2 -o crt2.crt

../target/release/adac-cli verify -p crt2.crt
```

### Sign Test 3 certificate

```
../target/release/adac-cli sign -c test-config.toml \
    -p resources/keys/EcdsaP384Key-1.pk8 -r EcdsaP384Key-2.pub \
    -i inter.crt -s crt3 -o crt3.crt

../target/release/adac-cli verify -p crt3.crt
```
