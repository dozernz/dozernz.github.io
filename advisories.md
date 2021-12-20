---
layout: page
title: Advisories
permalink: /advisories/
---

A list of my (old) public advisories. Several of these contain remote preauth -> root exploit bug chains, and all contain full proof of concept exploit details.

#### [SaltStack Salt - March 2021](/uploads/salt.txt)
CVE-2021-3197, CVE-2021-25281 and CVE-2021-25282, discovered via variant analysis. [Post here](/posts/saltapi-vulns).

#### [Calibre - December 2019](/uploads/calibre-xxe.txt)
Straightforward XXE then exfiltration of the read file from inside the sandbox. [Launchpad Ref](https://bugs.launchpad.net/calibre/+bug/1857800), fixed in 4.8. POC at [poc3.epub](/uploads/poc3.epub)

#### [Cisco WSA - July 2016](https://web.archive.org/web/20171011143514/https://security-assessment.com/files/documents/advisory/Cisco-WSA-Advisory-release.pdf)
Partial Auth bypass, authenticated code execution, Stored XSS in Cisco Web Security Appliance

#### [Cisco Prime Infrastructure - Jun 2016](https://web.archive.org/web/20171111052901/https://security-assessment.com/files/documents/advisory/Cisco-Prime-Infrastructure-Release.pdf)
API authentication bypass, authenticated code execution, Privilege Escalation, unauthenicated XXE and unauthenticated SQLi

#### [Cisco Prime vNAM - Jun 2016](https://web.archive.org/web/20171111052922/https://security-assessment.com/files/documents/advisory/Cisco-Prime-vNam.pdf)
Unauthenticated remote code execution, privesc, subshell breakout in Cisco Prime vNAM

#### [Kaltura - Mar 2016](https://web.archive.org/web/20170223025622/https://security-assessment.com/files/documents/advisory/Kaltura-Multiple-Vulns.pdf)
Preauth RCE via unserialize, authenticated file upload, preauth SSRF, cryptographic weakness leading to account takeover, stored XSS

#### [CYAN - Nov 2015](https://web.archive.org/web/20171111053106/http://www.security-assessment.com/files/documents/advisory/Cyan%20Secure%20Web%20-%20Multiple%20Vulnerabilities.pdf)
Authentication byass, authed file write to shell, privilege escalation.

#### [Symantec Web Gateway - Sep 2015](https://web.archive.org/web/20171111055555/http://www.security-assessment.com/files/documents/advisory/Symantec-advisory-Final.pdf)
Authenticated SQLi, authenticated command injection

#### [Silver Peak VXOA - Sep 2015](https://web.archive.org/web/20171111055349/http://www.security-assessment.com/files/documents/advisory/Silverpeak-Advisory-Final.pdf)
Preauth file read, post auth command injection, mass assignment, shell file upload , hardcoded admin credentials, subshell breakout.

#### [Citrix Netscaler - Jun 2015](https://web.archive.org/web/20171111053025/http://www.security-assessment.com/files/documents/advisory/Citrix-Netscaler-Final.pdf)
Authenticated command injection, privilege escalation

#### [WedgeOS - Jun 2015](https://web.archive.org/web/20171111055904/http://www.security-assessment.com/files/documents/advisory/WedgeOS-Final.pdf)
Preauth file read, authenticated command injection, privilege escalation

#### [Watchguard XCS - Jun 2015](https://web.archive.org/web/20171111055843/http://www.security-assessment.com/files/documents/advisory/Watchguard-XCS-final.pdf)
Preauth SQLi, command injection, privilege escalation

#### [Liferay Portal - Feb 2015](https://web.archive.org/web/20171111054032/http://www.security-assessment.com/files/documents/advisory/LR-file-upload.pdf)
Authenticated file upload to shell
