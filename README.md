# ECDSA
Minimalistic ECDSA/ECDH Tool written in Go 
### Usage:
<pre> -derive
       Derive shared secret key.
 -key string
       Private/Public key.
 -keygen
       Generate keypair.
 -pub string
       Remote's side Public key.
 -sign
       Sign with Private key.
 -signature string
       Signature.
 -verify
       Verify with Public key.</pre>
### Examples:
#### Asymmetric keypair generation:
<pre>./ecdsa -keygen</pre>
#### Shared key negociation (ECDH):
<pre>./ecdsa -derive -key $prvkey -pub $pubkey</pre>
#### Sign a file (ECDSA):
<pre>./ecdsa -sign -key $private < file.ext > sign.txt
sign=$(cat sign.txt)
./ecdsa -verify -key $public -signature $sign < file.ext
</pre>
## License
This project is licensed under the ISC License.
##### Copyright (c) 2020-2021 Pedro Albanese - ALBANESE Lab.
