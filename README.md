# ECDSA Signer
Minimalistic ECDSA Signer written in Go 
### Usage:
<pre> -key string
       Private/Public key.
 -keygen
       Generate keypair.
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
<pre>./gosttk -derive -key $prvkey -pub $pubkey</pre>
#### Sign a file (ECDSA):
<pre>./ecdsa -sign -key $private < file.ext > sign.txt
sign=$(cat sign.txt)
./ecdsa -verify -key $public -signature $sign < file.ext
</pre>
## License
This project is licensed under the ISC License.
##### Copyright (c) 2020-2021 Pedro Albanese - ALBANESE Lab.
