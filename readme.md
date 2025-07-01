<!--lint disable awesome-heading-->

<p align="center">
  <a href="https://github.com/kdeldycke/awesome-iam#readme">
    <img src="https://raw.githubusercontent.com/kdeldycke/awesome-iam/main/assets/awesome-iam-header.jpg" alt="Awesome IAM">
  </a>
</p>

<p align="center">
  <a href="https://github.com/kdeldycke/awesome-iam#readme" hreflang="en"><img src="https://img.shields.io/badge/lang-English-blue?style=flat-square" lang="en" alt="English"></a>
  <a href="https://github.com/kdeldycke/awesome-iam/blob/main/readme.zh.md" hreflang="zh"><img src="https://img.shields.io/badge/lang-中文-blue?style=flat-square" lang="zh" alt="中文"></a>
</p>

<p align="center">
  <sup>This list is <a href="#sponsor-def">sponsored<sup id="sponsor-ref">[0]</sup></a> by:</sup><br>
</p>

<p align="center">
  <a href="https://www.descope.com/?utm_source=awesome-iam&utm_medium=referral&utm_campaign=awesome-iam-oss-sponsorship">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/kdeldycke/awesome-iam/main/assets/descope-logo-dark-background.svg">
      <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/kdeldycke/awesome-iam/main/assets/descope-logo-light-background.svg">
      <img width="300" src="https://raw.githubusercontent.com/kdeldycke/awesome-iam/main/assets/descope-logo-light-background.svg">
    </picture>
    <br/>
    <strong>Drag and drop your auth.</strong><br/>
    Add authentication, user management, and authorization to your app with a few lines of code.
  </a>
  <br/><br/>
</p>

<p align="center">
  <a href="https://www.cerbos.dev/?utm_campaign=brand_cerbos&utm_source=awesome_iam&utm_medium=github&utm_content=&utm_term=">
    <img width="600" src="https://raw.githubusercontent.com/kdeldycke/awesome-iam/main/assets/cerbos-banner.svg">
    <br/>
    Build scalable, fine-grained authorization for your apps. <strong>Try Cerbos</strong>, an authorization management system for authoring, testing, and deploying access policies.
  </a>
  <br/><br/>
</p>

<!-- Comment this sponsorship call-to-action if there is a sponsor logo to increase its impact. -->

<!--
<p align="center">
  <a href="https://github.com/sponsors/kdeldycke">
    <strong>Yᴏᴜʀ Iᴅᴇɴᴛɪᴛʏ & Aᴜᴛʜᴇɴᴛɪᴄᴀᴛɪᴏɴ Pʀᴏᴅᴜᴄᴛ ʜᴇʀᴇ!</strong>
    <br/>
    <sup>Add a link to your company or project here: back me up via a GitHub sponsorship.</sup>
  </a>
  <br/><br/>
</p>
-->

---

<p align="center">
  <i>Trusting is hard. Knowing who to trust, even harder.</i><br>
  — Maria V. Snyder<sup id="intro-quote-ref"><a href="#intro-quote-def">[1]</a></sup>
</p>

<!--lint disable double-link-->

[IAM](https://en.wikipedia.org/wiki/Identity_management) stands for Identity and Access Management. It is a complex domain which covers **user accounts, authentication, authorization, roles, permissions and privacy**. It is an essential pillar of the cloud stack, where users, products and security meets. The [other pillar being billing & payments 💰](https://github.com/kdeldycke/awesome-billing/).

This curated [![Awesome](https://awesome.re/badge-flat.svg)](https://github.com/sindresorhus/awesome) list expose all the technologies, protocols and jargon of the domain in a comprehensive and actionable manner.

<!--lint enable double-link-->

## Contents

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Overview](#overview)
- [Security](#security)
- [Account Management](#account-management)
- [Cryptography](#cryptography)
  - [Identifiers](#identifiers)
- [Zero-trust Network](#zero-trust-network)
- [Authentication](#authentication)
- [Password-based auth](#password-based-auth)
- [Multi-factor auth](#multi-factor-auth)
  - [SMS-based](#sms-based)
- [Password-less auth](#password-less-auth)
  - [WebAuthn](#webauthn)
  - [Security key](#security-key)
  - [Public-Key Infrastructure (PKI)](#public-key-infrastructure-pki)
  - [JWT](#jwt)
- [Authorization](#authorization)
  - [Policy models](#policy-models)
  - [RBAC frameworks](#rbac-frameworks)
  - [ABAC frameworks](#abac-frameworks)
  - [ReBAC frameworks](#rebac-frameworks)
  - [AWS policy tools](#aws-policy-tools)
  - [Macaroons](#macaroons)
  - [Other tools](#other-tools)
- [OAuth2 & OpenID](#oauth2--openid)
- [SAML](#saml)
- [Secret Management](#secret-management)
  - [Hardware Security Module (HSM)](#hardware-security-module-hsm)
- [Trust & Safety](#trust--safety)
  - [User Identity](#user-identity)
  - [Fraud](#fraud)
  - [Moderation](#moderation)
  - [Threat Intelligence](#threat-intelligence)
  - [Captcha](#captcha)
- [Blocklists](#blocklists)
  - [Hostnames and Subdomains](#hostnames-and-subdomains)
  - [Emails](#emails)
  - [Reserved IDs](#reserved-ids)
  - [Profanity](#profanity)
- [Privacy](#privacy)
  - [Anonymization](#anonymization)
  - [GDPR](#gdpr)
- [UX/UI](#uxui)
- [Competitive Analysis](#competitive-analysis)
- [History](#history)

<!-- mdformat-toc end -->

## Overview

<img align="right" width="50%" src="./assets/cloud-software-stack-iam.jpg"/>

In a Stanford class providing an [overview of cloud computing](https://web.stanford.edu/class/cs349d/docs/L01_overview.pdf), the software architecture of the platform is described as in the right diagram →

Here we set out the big picture: definition and strategic importance of the domain, its place in the larger ecosystem, plus some critical features.

- [The EnterpriseReady SaaS Feature Guides](https://www.enterpriseready.io) - The majority of the features making B2B users happy will be implemented by the IAM perimeter.

- [IAM is hard. It's really hard.](https://web.archive.org/web/20200809095434/https://twitter.com/kmcquade3/status/1291801858676228098) - “Overly permissive AWS IAM policies that allowed `s3:GetObject` to `*` (all) resources”, led to \$80 million fine for Capital One. The only reason why you can't overlook IAM as a business owner.

- [IAM Is The Real Cloud Lock-In](https://forrestbrazeal.com/2019/02/18/cloud-irregular-iam-is-the-real-cloud-lock-in/) - A little *click-baity*, but author admit that “It depends on how much you trust them to 1. Stay in business; 2. Not jack up your prices; 3. Not deprecate services out from under you; 4. Provide more value to you in business acceleration than they take away in flexibility.”

## Security

Security is one of the most central pillar of IAM foundations. Here are some broad concepts.

- [Enterprise Information Security](https://infosec.mozilla.org) - Mozilla's security and access guidelines.

- [Mitigating Cloud Vulnerabilities](https://web.archive.org/web/20250529050934/https://media.defense.gov/2020/Jan/22/2002237484/-1/-1/0/CSI-MITIGATING-CLOUD-VULNERABILITIES_20200121.PDF) - “This document divides cloud vulnerabilities into four classes (misconfiguration, poor access control, shared tenancy vulnerabilities, and supply chain vulnerabilities)”.

- [Cartography](https://github.com/lyft/cartography) - A Neo4J-based tool to map out dependencies and relationships between services and resources. Supports AWS, GCP, GSuite, Okta and GitHub.

- [Open guide to AWS Security and IAM](https://github.com/open-guides/og-aws#security-and-iam)

## Account Management

The foundation of IAM: the definition and life-cycle of users, groups, roles and permissions.

- [As a user, I want…](https://mobile.twitter.com/oktopushup/status/1030457418206068736) - A meta-critic of account management, in which features expected by the business clash with real user needs, in the form of user stories written by a fictional project manager.

- [Things end users care about but programmers don't](https://instadeq.com/blog/posts/things-end-users-care-about-but-programmers-dont/) - In the same spirit as above, but broader: all the little things we overlook as developers but users really care about. In the top of that list lies account-centric features, diverse integration and import/export tools. I.e. all the enterprise customers needs to cover.

- [Separate the account, user and login/auth details](https://news.ycombinator.com/item?id=21151830) - Sound advice to lay down the foundation of a future-proof IAM API.

- [Identity Beyond Usernames](https://lord.io/blog/2020/usernames/) - On the concept of usernames as identifiers, and the complexities introduced when unicode characters meets uniqueness requirements.

- [Kratos](https://github.com/ory/kratos) - User login, user registration, 2FA and profile management.

- [Conjur](https://github.com/cyberark/conjur) - Automatically secures secrets used by privileged users and machine identities.

- [SuperTokens](https://github.com/supertokens/supertokens-core) - Open-source project for login and session management which supports passwordless, social login, email and phone logins.

- [UserFrosting](https://github.com/userfrosting/UserFrosting) - Modern PHP user login and management framework.

## Cryptography

The whole authentication stack is based on cryptography primitives. This can't be overlooked.

- [Cryptographic Right Answers](https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html) - An up to date set of recommendations for developers who are not cryptography engineers. There's even a [shorter summary](https://news.ycombinator.com/item?id=16749140) available.

- [Real World Crypto Symposium](https://rwc.iacr.org) - Aims to bring together cryptography researchers with developers, focusing on uses in real-world environments such as the Internet, the cloud, and embedded devices.

- [An Overview of Cryptography](https://www.garykessler.net/library/crypto.html) - “This paper has two major purposes. The first is to define some of the terms and concepts behind basic cryptographic methods, and to offer a way to compare the myriad cryptographic schemes in use today. The second is to provide some real examples of cryptography in use today.”

- [Papers we love: Cryptography](https://github.com/papers-we-love/papers-we-love/blob/master/cryptography/README.md) - Foundational papers of cryptography.

- [Lifetimes of cryptographic hash functions](http://valerieaurora.org/hash.html) - “If you are using compare-by-hash to generate addresses for data that can be supplied by malicious users, you should have a plan to migrate to a new hash every few years”.

### Identifiers

Tokens, primary keys, UUIDs, … Whatever the end use, you'll have to generate these numbers with some randomness and uniqueness properties.

- [Security Recommendations for Any Device that Depends on Randomly-Generated Numbers](https://www.av8n.com/computer/htm/secure-random.htm) - “The phrase ‘random number generator’ should be parsed as follows: It is a random generator of numbers. It is not a generator of random numbers.”

- [RFC #4122: UUID - Security Considerations](https://www.rfc-editor.org/rfc/rfc4122#section-6) - “Do not assume that UUIDs are hard to guess; they should not be used as security capabilities (identifiers whose mere possession grants access)”. UUIDs are designed to be unique, not to be random or unpredictable: do not use UUIDs as a secret.

- [Awesome Identifiers](https://adileo.github.io/awesome-identifiers/) - A benchmark of all identifier formats.

- [Awesome GUID](https://github.com/secretGeek/AwesomeGUID) - Funny take on the global aspect of unique identifiers.

## Zero-trust Network

Zero trust network security operates under the principle “never trust, always verify”.

- [BeyondCorp: A New Approach to Enterprise Security](https://www.usenix.org/system/files/login/articles/login_dec14_02_ward.pdf) - Quick overview of Google's Zero-trust Network initiative.

- [What is BeyondCorp? What is Identity-Aware Proxy?](https://medium.com/google-cloud/what-is-beyondcorp-what-is-identity-aware-proxy-de525d9b3f90) - More companies add extra layers of VPNs, firewalls, restrictions and constraints, resulting in a terrible experience and a slight security gain. There's a better way.

- [oathkeeper](https://github.com/ory/oathkeeper) - Identity & Access Proxy and Access Control Decision API that authenticates, authorizes, and mutates incoming HTTP requests. Inspired by the BeyondCorp / Zero Trust white paper.

- [transcend](https://github.com/cogolabs/transcend) - BeyondCorp-inspired Access Proxy server.

- [Pomerium](https://github.com/pomerium/pomerium) - An identity-aware proxy that enables secure access to internal applications.

- [heimdall](https://github.com/dadrus/heimdall) - A cloud-native, identity-aware proxy and policy enforcement point that orchestrates authentication and authorization systems via versatile rules, supporting protocol-agnostic identity propagation.

## Authentication

Protocols and technologies to verify that you are who you pretend to be.

- [API Tokens: A Tedious Survey](https://fly.io/blog/api-tokens-a-tedious-survey/) - An overview and comparison of all token-based authentication schemes for end-user APIs.

- [A Child's Garden of Inter-Service Authentication Schemes](https://web.archive.org/web/20200507173734/https://latacora.micro.blog/a-childs-garden/) - In the same spirit as above, but this time at the service level.

- [Scaling backend authentication at Facebook](https://www.youtube.com/watch?v=kY-Bkv3qxMc) - How-to in a nutshell: 1. Small root of trust; 2. TLS isn't enough; 3. Certificate-based tokens; 4. Crypto Auth Tokens (CATs). See the [slides](https://rwc.iacr.org/2018/Slides/Lewi.pdf) for more details.

## Password-based auth

The oldest scheme for auth.

- [The new NIST password guidance](https://pciguru.wordpress.com/2019/03/11/the-new-nist-password-guidance/) - A summary of [NIST Special Publication 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) covering new password complexity guidelines.

- [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) - The only way to slow down offline attacks is by carefully choosing hash algorithms that are as resource intensive as possible.

- [Password expiration is dead](https://techcrunch.com/2019/06/02/password-expiration-is-dead-long-live-your-passwords/) - Recent scientific research calls into question the value of many long-standing password-security practices such as password expiration policies, and points instead to better alternatives such as enforcing banned-password lists and MFA.

- [Practical Recommendations for Stronger, More Usable Passwords](http://www.andrew.cmu.edu/user/nicolasc/publications/Tan-CCS20.pdf) - This study recommend the association of: blocklist checks against commonly leaked passwords, password policies without character-class requirements, minimum-strength policies.

- [Banks, Arbitrary Password Restrictions and Why They Don't Matter](https://www.troyhunt.com/banks-arbitrary-password-restrictions-and-why-they-dont-matter/) - “Arbitrary low limits on length and character composition are bad. They look bad, they lead to negative speculation about security posture and they break tools like password managers.”

- [Dumb Password Rules](https://github.com/dumb-password-rules/dumb-password-rules) - Shaming sites with dumb password rules.

- [Plain Text Offenders](https://plaintextoffenders.com/about/) - Public shaming of websites storing passwords in plain text.

- [Password Manager Resources](https://github.com/apple/password-manager-resources) - A collection of password rules, change URLs and quirks by sites.

- [A Well-Known URL for Changing Passwords](https://github.com/WICG/change-password-url) - Specification defining site resource for password updates.

- [How to change the hashing scheme of already hashed user's passwords](https://news.ycombinator.com/item?id=20109360) - Good news: you're not stuck with a legacy password saving scheme. Here is a trick to transparently upgrade to stronger hashing algorithm.

## Multi-factor auth

Building upon password-only auth, users are requested in these schemes to present two or more pieces of evidence (or factors).

- [Breaking Password Dependencies: Challenges in the Final Mile at Microsoft](https://www.youtube.com/watch?v=B_mhJO2qHlQ) - The primary source of account hacks is password spraying (on legacy auth like SMTP, IMAP, POP, etc.), second is replay attack. Takeaway: password are insecure, use and enforce MFA.

- [Beyond Passwords: 2FA, U2F and Google Advanced Protection](https://www.troyhunt.com/beyond-passwords-2fa-u2f-and-google-advanced-protection/) - An excellent walk-trough over all these technologies.

- [A Comparative Long-Term Study of Fallback Authentication](https://maximiliangolla.com/files/2019/papers/usec2019-30-wip-fallback-long-term-study-finalv5.pdf) - Key take-away: “schemes based on email and SMS are more usable. Mechanisms based on designated trustees and personal knowledge questions, on the other hand, fall short, both in terms of convenience and efficiency.”

- [Secrets, Lies, and Account Recovery: Lessons from the Use of Personal Knowledge Questions at Google](https://static.googleusercontent.com/media/research.google.com/en/us/pubs/archive/43783.pdf) - “Our analysis confirms that secret questions generally offer a security level that is far lower than user-chosen passwords. (…) Surprisingly, we found that a significant cause of this insecurity is that users often don't answer truthfully. (…) On the usability side, we show that secret answers have surprisingly poor memorability”.

- [How effective is basic account hygiene at preventing hijacking](https://security.googleblog.com/2019/05/new-research-how-effective-is-basic.html) - Google security team's data shows 2FA blocks 100% of automated bot hacks.

- [Your Pa\$\$word doesn't matter](https://techcommunity.microsoft.com/t5/Azure-Active-Directory-Identity/Your-Pa-word-doesn-t-matter/ba-p/731984) - Same conclusion as above from Microsoft: “Based on our studies, your account is more than 99.9% less likely to be compromised if you use MFA.”

- [Attacking Google Authenticator](https://unix-ninja.com/p/attacking_google_authenticator) - Probably on the verge of paranoia, but might be a reason to rate limit 2FA validation attempts.

- [Compromising online accounts by cracking voicemail systems](https://www.martinvigo.com/voicemailcracker/) - Or why you should not rely on automated phone calls as a method to reach the user and reset passwords, 2FA or for any kind of verification. Not unlike SMS-based 2FA, it is currently insecure and can be compromised by the way of its weakest link: voicemail systems.

- [Getting 2FA Right in 2019](https://blog.trailofbits.com/2019/06/20/getting-2fa-right-in-2019/) - On the UX aspects of 2FA.

- [2FA is missing a key feature](https://syslog.ravelin.com/2fa-is-missing-a-key-feature-c781c3861db) - “When my 2FA code is entered incorrectly I'd like to know about it”.

- [SMS Multifactor Authentication in Antarctica](https://brr.fyi/posts/sms-mfa) - Doesn't work because there are no cellphone towers at stations in Antarctica.

- [Authelia](https://github.com/authelia/authelia) - Open-source authentication and authorization server providing two-factor authentication and single sign-on (SSO) for your applications via a web portal.

- [Kanidm](https://github.com/kanidm/kanidm) - Simple, secure and fast identity management platform.

### SMS-based

TL;DR: don't. For details, see articles below.

- [SMS 2FA auth is deprecated by NIST](https://techcrunch.com/2016/07/25/nist-declares-the-age-of-sms-based-2-factor-authentication-over/) - NIST has said that 2FA via SMS is bad and awful since 2016.

- [SMS: The most popular and least secure 2FA method](https://www.allthingsauth.com/2018/02/27/sms-the-most-popular-and-least-secure-2fa-method/)

- [Is SMS 2FA Secure? No.](https://www.issms2fasecure.com) - Definitive research project demonstrating successful attempts at SIM swapping.

- [Hackers Hit Twitter C.E.O. Jack Dorsey in a 'SIM Swap.' You're at Risk, Too.](https://archive.ph/AhNAI)

- [AT&T rep handed control of his cellphone account to a hacker](https://www.theregister.co.uk/2017/07/10/att_falls_for_hacker_tricks/)

- [The Most Expensive Lesson Of My Life: Details of SIM port hack](https://medium.com/coinmonks/the-most-expensive-lesson-of-my-life-details-of-sim-port-hack-35de11517124)

- [SIM swap horror story](https://www.zdnet.com/article/sim-swap-horror-story-ive-lost-decades-of-data-and-google-wont-lift-a-finger/)

- [AWS is on its way to deprecate SMS-based 2FA](https://aws.amazon.com/iam/details/mfa/) - “We encourage you to use MFA through a U2F security key, hardware device, or virtual (software-based) MFA device. You can continue using this feature until January 31, 2019.”

## Password-less auth

- [An argument for passwordless](https://web.archive.org/web/20190515230752/https://biarity.gitlab.io/2018/02/23/passwordless/) - Passwords are not the be-all and end-all of user authentication. This article tries to tell you why.

- [Magic Links – Are they Actually Outdated?](https://zitadel.com/blog/magic-links) - What are magic links, their origin, pros and cons.

### WebAuthn

Part of the [FIDO2 project](https://en.wikipedia.org/wiki/FIDO_Alliance#FIDO2), and also known under the user-friendly name of *passkeys*.

- [WebAuthn guide](https://webauthn.guide) - Introduce WebAuthn as a standard supported by all major browsers, and allowing “servers to register and authenticate users using public key cryptography instead of a password”.

- [Clearing up some misconceptions about Passkeys](https://www.stavros.io/posts/clearing-up-some-passkeys-misconceptions/) - Or why passkeys are not worse than passwords.

### Security key

- [Webauthn and security keys](https://www.imperialviolet.org/2018/03/27/webauthn.html) - Describe how authentication works with security keys, details the protocols, and how they articulates with WebAuthn. Key takeaway: “There is no way to create a U2F key with webauthn however. (…) So complete the transition to webauthn of your login process first, then transition registration.”

- [Getting started with security keys](https://paulstamatiou.com/getting-started-with-security-keys/) - A practical guide to stay safe online and prevent phishing with FIDO2, WebAuthn and security keys.

- [Solo](https://github.com/solokeys/solo) - Open security key supporting FIDO2 & U2F over USB + NFC.

- [OpenSK](https://github.com/google/OpenSK) - Open-source implementation for security keys written in Rust that supports both FIDO U2F and FIDO2 standards.

- [YubiKey Guide](https://github.com/drduh/YubiKey-Guide) - Guide to using YubiKey as a SmartCard for storing GPG encryption, signing and authentication keys, which can also be used for SSH. Many of the principles in this document are applicable to other smart card devices.

- [YubiKey at Datadog](https://github.com/DataDog/yubikey) - Guide to setup Yubikey, U2F, GPG, git, SSH, Keybase, VMware Fusion and Docker Content Trust.

### Public-Key Infrastructure (PKI)

Certificate-based authentication.

- [PKI for busy people](https://gist.github.com/hoffa/5a939fd0f3bcd2a6a0e4754cb2cf3f1b) - Quick overview of the important stuff.

- [Everything you should know about certificates and PKI but are too afraid to ask](https://smallstep.com/blog/everything-pki.html) - PKI lets you define a system cryptographically. It's universal and vendor neutral.

- [`lemur`](https://github.com/Netflix/lemur) - Acts as a broker between CAs and environments, providing a central portal for developers to issue TLS certificates with 'sane' defaults.

- [CFSSL](https://github.com/cloudflare/cfssl) - A swiss army knife for PKI/TLS by CloudFlare. Command line tool and an HTTP API server for signing, verifying, and bundling TLS certificates.

- [JA3](https://github.com/salesforce/ja3) - Method for creating SSL/TLS client fingerprints that should be easy to produce on any platform and can be easily shared for threat intelligence.

### JWT

[JSON Web Token](https://en.wikipedia.org/wiki/JSON_Web_Token) is a bearer's token.

- [Introduction to JSON Web Tokens](https://jwt.io/introduction/) - Get up to speed on JWT with this article.

- [Learn how to use JWT for Authentication](https://github.com/dwyl/learn-json-web-tokens) - Learn how to use JWT to secure your web app.

- [Using JSON Web Tokens as API Keys](https://auth0.com/blog/using-json-web-tokens-as-api-keys/) - Compared to API keys, JWTs offers granular security, homogeneous auth architecture, decentralized issuance, OAuth2 compliance, debuggability, expiration control, device management.

- [Hardcoded secrets, unverified tokens, and other common JWT mistakes](https://r2c.dev/blog/2020/hardcoded-secrets-unverified-tokens-and-other-common-jwt-mistakes/) - A good recap of all JWT pitfalls.

- [Adding JSON Web Token API Keys to a DenyList](https://auth0.com/blog/denylist-json-web-token-api-keys/) - On token invalidation.

- [Stop using JWT for sessions](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/) - And [why your "solution" doesn't work](http://cryto.net/%7Ejoepie91/blog/2016/06/19/stop-using-jwt-for-sessions-part-2-why-your-solution-doesnt-work/), because [stateless JWT tokens cannot be invalidated or updated](https://news.ycombinator.com/item?id=18354141). They will introduce either size issues or security issues depending on where you store them. Stateful JWT tokens are functionally the same as session cookies, but without the battle-tested and well-reviewed implementations or client support.

- [JWT, JWS and JWE for Not So Dummies!](https://medium.facilelogin.com/jwt-jws-and-jwe-for-not-so-dummies-b63310d201a3) - A signed JWT is known as a JWS (JSON Web Signature). In fact a JWT does not exist itself — either it has to be a JWS or a JWE (JSON Web Encryption). Its like an abstract class — the JWS and JWE are the concrete implementations.

- [JOSE is a Bad Standard That Everyone Should Avoid](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid) - The standards are either completely broken or complex minefields hard to navigate.

- [JWT.io](https://jwt.io) - Allows you to decode, verify and generate JWT.

- [`loginsrv`](https://github.com/tarent/loginsrv) - Standalone minimalistic login server providing a JWT login for multiple login backends (htpasswd, OSIAM, user/password, HTTP basic authentication, OAuth2: GitHub, Google, Bitbucket, Facebook, GitLab).

- [jwtXploiter](https://github.com/DontPanicO/jwtXploiter) - A tool to test security of json web token.

## Authorization

Now we know you are you. But are you allowed to do what you want to do?

Policy specification is the science, enforcement is the art.

### Policy models

As a concept, access control policies can be designed to follow very different archetypes, from classic [Access Control Lists](https://en.wikipedia.org/wiki/Access-control_list) to Role Based Access Control. In this section we explore lots of different patterns and architectures.

- [Why Authorization is Hard](https://www.osohq.com/post/why-authorization-is-hard) - Because it needs multiple tradeoffs on Enforcement which is required in so many places, on Decision architecture to split business logic from authorization logic, and on Modeling to balance power and complexity.

- [The never-ending product requirements of user authorization](https://alexolivier.me/posts/the-never-ending-product-requirements-of-user-authorization) - How a simple authorization model based on roles is not enough and gets complicated fast due to product packaging, data locality, enterprise organizations and compliance.

- [RBAC like it was meant to be](https://tailscale.com/blog/rbac-like-it-was-meant-to-be/) - How we got from DAC (unix permissions, secret URL), to MAC (DRM, MFA, 2FA, SELinux), to RBAC. Details how the latter allows for better modeling of policies, ACLs, users and groups.

- [The Case for Granular Permissions](https://cerbos.dev/blog/the-case-for-granular-permissions) - Discuss the limitations of RBAC and how ABAC (Attribute-Based Access Control) addresses them.

- [In Search For a Perfect Access Control System](https://web.archive.org/web/20240421203937/https://goteleport.com/blog/access-controls/) - The historical origins of authorization schemes. Hints at the future of sharing, trust and delegation between different teams and organizations.

- [GCP's IAM syntax is better than AWS's](https://ucarion.com/iam-operation-syntax) - The minutiae of permission design in GCP improves the developer's experience.

- [Semantic-based Automated Reasoning for AWS Access Policies using SMT](https://d1.awsstatic.com/Security/pdfs/Semantic_Based_Automated_Reasoning_for_AWS_Access_Policies_Using_SMT.pdf) - Zelkova is how AWS does it. This system perform symbolic analysis of IAM policies, and solve the reachability of resources according user's rights and access constraints. Also see the higher-level [introduction given at re:inforce 2019](https://youtu.be/x6wsTFnU3eY?t=2111).

- [Authorization Academy](https://www.osohq.com/academy) - An in-depth, vendor-agnostic treatment of authorization that emphasizes mental models. This guide shows the reader how to think about their authorization needs in order to make good decisions about their authorization architecture and model.

- [Service-to-service authorization: A guide to non-user principals](https://www.cerbos.dev/blog/service-to-service-authorization) - Discover how assigning identities to services (non-user principals) can simplify authentication, enhance security, and streamline authorization in complex distributed systems. A useful guide for IAM teams managing microservices and APIs.

### RBAC frameworks

[Role-Based Access Control](https://en.wikipedia.org/wiki/Role-based_access_control) is the classical model to map users to permissions by the way of roles.

- [Athenz](https://github.com/yahoo/athenz) - Set of services and libraries supporting service authentication and role-based authorization for provisioning and configuration.

- [Biscuit](https://www.clever-cloud.com/blog/engineering/2021/04/12/introduction-to-biscuit/) - Biscuit merge concepts from cookies, JWTs, macaroons and Open Policy Agent. “It provide a logic language based on Datalog to write authorization policies. It can store data, like JWT, or small conditions like Macaroons, but it is also able to represent more complex rules like role-based access control, delegation, hierarchies.”

- [Oso](https://github.com/osohq/oso) - A batteries-included library for building authorization in your application.

- [Cerbos](https://github.com/cerbos/cerbos) - An authorization endpoint to write context-aware access control policies.

### ABAC frameworks

[Attribute-Based Access Control](https://en.wikipedia.org/wiki/Attribute-based_access_control) is an evolution of RBAC, in which roles are replaced by attributes, allowing the implementation of more complex policy-based access control.

- [Keto](https://github.com/ory/keto) - Policy decision point. It uses a set of access control policies, similar to AWS policies, in order to determine whether a subject is authorized to perform a certain action on a resource.

- [Ladon](https://github.com/ory/ladon) - Access control library, inspired by AWS.

- [Casbin](https://github.com/casbin/casbin) - Open-source access control library for Golang projects.

- [Open Policy Agent](https://github.com/open-policy-agent/opa) - An open-source general-purpose decision engine to create and enforce ABAC policies.

### ReBAC frameworks

The [Relationship-Based Access Control](https://en.wikipedia.org/wiki/Relationship-based_access_control) model is a more flexible and powerful version of RBAC and is the preferred one for cloud systems.

- [Zanzibar: Google's Consistent, Global Authorization System](https://ai.google/research/pubs/pub48190) - Scales to trillions of access control lists and millions of authorization requests per second to support services used by billions of people. It has maintained 95th-percentile latency of less than 10 milliseconds and availability of greater than 99.999% over 3 years of production use. [Other bits not in the paper](https://twitter.com/LeaKissner/status/1136626971566149633). [Zanzibar Academy](https://zanzibar.academy/) is a site dedicated to explaining how Zanzibar works.

- [SpiceDB](https://github.com/authzed/spicedb) - An open source database system for managing security-critical application permissions inspired by Zanzibar.

- [Permify](https://github.com/Permify/permify) - Another open-source authorization as a service inspired by Google Zanzibar, and see [how it compares to other Zanzibar-inspired tools](https://permify.notion.site/Differentiation-Between-Zanzibar-Products-ad4732da62e64655bc82d3abe25f48b6).

- [Topaz](https://github.com/aserto-dev/topaz) - An open-source project which combines the policy-as-code and decision logging of OPA with a Zanzibar-modeled directory.

- [Open Policy Administration Layer](https://github.com/permitio/opal) - Open Source administration layer for OPA, detecting changes to both policy and policy data in realtime and pushing live updates to OPA agents. OPAL brings open-policy up to the speed needed by live applications.

- [Warrant](https://github.com/warrant-dev/warrant) - A relationship based access control (ReBAC) engine (inspired by Google Zanzibar) also capable of enforcing any authorization paradigm, including RBAC and ABAC.

### AWS policy tools

Tools and resources exclusively targeting the [AWS IAM policies](http://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html) ecosystem.

- [An AWS IAM Security Tooling Reference](https://ramimac.me/aws-iam-tools-2024) - A comprehensive list of (maintained) tools for AWS IAM.

- [Become an AWS IAM Policy Ninja](https://www.youtube.com/watch?v=y7-fAT3z8Lo) - “In my nearly 5 years at Amazon, I carve out a little time each day, each week to look through the forums, customer tickets to try to find out where people are having trouble.”

- [AWS IAM Roles, a tale of unnecessary complexity](https://infosec.rodeo/posts/thoughts-on-aws-iam/) - The history of fast-growing AWS explains how the current scheme came to be, and how it compares to GCP's resource hierarchy.

- [Policy Sentry](https://github.com/salesforce/policy_sentry) - Writing security-conscious IAM Policies by hand can be very tedious and inefficient. Policy Sentry helps users to create least-privilege policies in a matter of seconds.

- [PolicyUniverse](https://github.com/Netflix-Skunkworks/policyuniverse) - Parse and process AWS policies, statements, ARNs, and wildcards.

- [IAM Floyd](https://github.com/udondan/iam-floyd) - AWS IAM policy statement generator with fluent interface. Helps with creating type safe IAM policies and writing more restrictive/secure statements by offering conditions and ARN generation via IntelliSense. Available for Node.js, Python, .Net and Java.

- [ConsoleMe](https://github.com/Netflix/consoleme) - A self-service tool for AWS that provides end-users and administrators credentials and console access to the onboarded accounts based on their authorization level of managing permissions across multiple accounts, while encouraging least-privilege permissions.

- [IAMbic](https://github.com/noqdev/iambic) - GitOps for IAM. The Terraform of Cloud IAM. IAMbic is a multi-cloud identity and access management (IAM) control plane that centralizes and simplifies cloud access and permissions. It maintains an eventually consistent, human-readable, bi-directional representation of IAM in version control.

### Macaroons

A clever curiosity to distribute and delegate authorization.

- [Google's Macaroons in Five Minutes or Less](https://blog.bren2010.io/blog/googles-macaroons) - If I'm given a Macaroon that authorizes me to perform some action(s) under certain restrictions, I can non-interactively build a second Macaroon with stricter restrictions that I can then give to you.

- [Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud](https://ai.google/research/pubs/pub41892) - Google's original paper.

- [Google paper's author compares Macaroons and JWTs](https://news.ycombinator.com/item?id=14294463) - As a consumer/verifier of macaroons, they allow you (through third-party caveats) to defer some authorization decisions to someone else. JWTs don't.

### Other tools

- [Gubernator](https://github.com/gubernator-io/gubernator) - High performance rate-limiting micro-service and library.

## OAuth2 & OpenID

[OAuth 2.0](https://en.wikipedia.org/wiki/OAuth#OAuth_2.0) is a *delegated authorization* framework. [OpenID Connect (OIDC)](https://en.wikipedia.org/wiki/OpenID_Connect) is an *authentication* layer on top of it.

The old *OpenID* is dead; the new *OpenID Connect* is very much not-dead.

- [Awesome OpenID Connect](https://github.com/cerberauth/awesome-openid-connect) - A curated list of providers, services, libraries, and resources for OpenID Connect.

- [An Illustrated Guide to OAuth and OpenID Connect](https://developer.okta.com/blog/2019/10/21/illustrated-guide-to-oauth-and-oidc) - Explain how these standards work using simplified illustrations.

- [OAuth 2 Simplified](https://aaronparecki.com/oauth-2-simplified/) - A reference article describing the protocol in simplified format to help developers and service providers implement it.

- [OAuth 2.0 and OpenID Connect (in plain English)](https://www.youtube.com/watch?v=996OiexHze0) - Starts with an historical context on how these standards came to be, clears up the innacuracies in the vocabulary, then details the protocols and its pitfalls to make it less intimidating.

- [OAuth in one picture](https://mobile.twitter.com/kamranahmedse/status/1276994010423361540) - A nice summary card.

- [How to Implement a Secure Central Authentication Service in Six Steps](https://shopify.engineering/implement-secure-central-authentication-service-six-steps) - Got multiple legacy systems to merge with their own login methods and accounts? Here is how to merge all that mess by the way of OIDC.

- [Open-Sourcing BuzzFeed's SSO Experience](https://increment.com/security/open-sourcing-buzzfeeds-single-sign-on-process/) - OAuth2-friendly adaptation of the Central Authentication Service (CAS) protocol. You'll find there good OAuth user flow diagrams.

- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc9700) - “Updates and extends the OAuth 2.0 Security Threat Model to incorporate practical experiences gathered since OAuth 2.0 was published and covers new threats relevant due to the broader application”.

- [Hidden OAuth attack vectors](https://portswigger.net/web-security/oauth) - How to identify and exploit some of the key vulnerabilities found in OAuth 2.0 authentication mechanisms.

- [PKCE Explained](https://www.loginradius.com/blog/engineering/pkce/) - “PKCE is used to provide one more security layer to the authorization code flow in OAuth and OpenID Connect.”

- [Hydra](https://www.ory.sh/hydra) - Open-source OIDC & OAuth2 Server Provider.

- [Keycloak](https://www.keycloak.org) - Open-source Identity and Access Management. Supports OIDC, OAuth 2 and SAML 2, LDAP and AD directories, password policies.

- [Casdoor](https://github.com/casbin/casdoor) - A UI-first centralized authentication / Single-Sign-On (SSO) platform based. Supports OIDC and OAuth 2, social logins, user management, 2FA based on Email and SMS.

- [authentik](https://goauthentik.io/) - Open-source Identity Provider similar to Keycloak.

- [ZITADEL](https://github.com/zitadel/zitadel) - An Open-Source solution built with Go and Angular to manage all your systems, users and service accounts together with their roles and external identities. ZITADEL provides you with OIDC, OAuth 2.0, login & register flows, passwordless and MFA authentication. All this is built on top of eventsourcing in combination with CQRS to provide a great audit trail.

- [a12n-server](https://github.com/curveball/a12n-server) - A simple authentication system which only implements the relevant parts of the OAuth2 standards.

- [Logto](https://github.com/logto-io/logto) - An IAM infrastructure for modern apps and SaaS products, supporting OIDC, OAuth 2.0 and SAML for authentication and authorization.

- [Authgear](https://github.com/authgear/authgear-server) - Open-source authentication-as-a-service solution. It includes the code for the server, AuthUI, the Portal, and Admin API.

## SAML

Security Assertion Markup Language (SAML) 2.0 is a means to exchange authorization and authentication between services, like OAuth/OpenID protocols above.

Typical SAML identity provider is an institution or a big corporation's internal SSO, while the typical OIDC/OAuth provider is a tech company that runs a data silo.

- [SAML vs. OAuth](https://web.archive.org/web/20230327071347/https://www.cloudflare.com/learning/access-management/what-is-oauth/) - “OAuth is a protocol for authorization: it ensures Bob goes to the right parking lot. In contrast, SAML is a protocol for authentication, or allowing Bob to get past the guardhouse.”

- [The Difference Between SAML 2.0 and OAuth 2.0](https://www.ubisecure.com/uncategorized/difference-between-saml-and-oauth/) - “Even though SAML was actually designed to be widely applicable, its contemporary usage is typically shifted towards enterprise SSO scenarios. On the other hand, OAuth was designed for use with applications on the Internet, especially for delegated authorisation.”

- [What's the Difference Between OAuth, OpenID Connect, and SAML?](https://www.okta.com/identity-101/whats-the-difference-between-oauth-openid-connect-and-saml/) - Identity is hard. Another take on the different protocol is always welcome to help makes sense of it all.

- [How SAML 2.0 Authentication Works](https://web.archive.org/web/20240421215604/https://goteleport.com/blog/how-saml-authentication-works/) - Overview of the how and why of SSO and SAML.

- [Web Single Sign-On, the SAML 2.0 perspective](https://blog.theodo.com/2019/06/web-single-sign-on-the-saml-2-0-perspective/) - Another naive explanation of SAML workflow in the context of corporate SSO implementation.

- [The Beer Drinker's Guide to SAML](https://duo.com/blog/the-beer-drinkers-guide-to-saml) - SAML is arcane at times. A another analogy might helps get more sense out of it.

- [SAML is insecure by design](https://joonas.fi/2021/08/saml-is-insecure-by-design/) - Not only weird, SAML is also insecure by design, as it relies on signatures based on XML canonicalization, not XML byte stream. Which means you can exploit XML parser/encoder differences.

- [The Difficulties of SAML Single Logout](https://wiki.shibboleth.net/confluence/display/CONCEPT/SLOIssues) - On the technical and UX issues of single logout implementations.

- [The SSO Wall of Shame](https://sso.tax) - A documented rant on the excessive pricing practiced by SaaS providers to activate SSO on their product. The author's point is, as a core security feature, SSO should be reasonably priced and not part of an exclusive tier.

## Secret Management

Architectures, software and hardware allowing the storage and usage of secrets to allow for authentication and authorization, while maintaining the chain of trust.

- [Secret at Scale at Netflix](https://www.youtube.com/watch?v=K0EOPddWpsE) - Solution based on blind signatures. See the [slides](https://rwc.iacr.org/2018/Slides/Mehta.pdf).

- [High Availability in Google's Internal KMS](https://www.youtube.com/watch?v=5T_c-lqgjso) - Not GCP's KMS, but the one at the core of their infrastructure. See the [slides](https://rwc.iacr.org/2018/Slides/Kanagala.pdf).

- [HashiCorp Vault](https://www.vaultproject.io) - Secure, store and tightly control access to tokens, passwords, certificates, encryption keys.

- [Infisical](https://github.com/Infisical/infisical) - An alternative to HashiCorp Vault.

- [`sops`](https://github.com/mozilla/sops) - Editor of encrypted files that supports YAML, JSON, ENV, INI and BINARY formats and encrypts with AWS KMS, GCP KMS, Azure Key Vault, age, and PGP.

- [`gitleaks`](https://github.com/zricethezav/gitleaks) - Audit git repos for secrets.

- [`truffleHog`](https://github.com/dxa4481/truffleHog) - Searches through git repositories for high entropy strings and secrets, digging deep into commit history.

- [Keywhiz](https://square.github.io/keywhiz/) - A system for managing and distributing secrets, which can fit well with a service oriented architecture (SOA).

- [`roca`](https://github.com/crocs-muni/roca) - Python module to check for weak RSA moduli in various key formats.

### Hardware Security Module (HSM)

HSMs are physical devices guaranteeing security of secret management at the hardware level.

- [HSM: What they are and why it's likely that you've (indirectly) used one today](https://rwc.iacr.org/2015/Slides/RWC-2015-Hampton.pdf) - Really basic overview of HSM usages.

- [Tidbits on AWS Cloud HSM hardware](https://news.ycombinator.com/item?id=16759383) - AWS CloudHSM Classic is backed by SafeNet's Luna HSM, current CloudHSM rely on Cavium's Nitrox, which allows for partitionable "virtual HSMs".

- [CrypTech](https://cryptech.is) - An open hardware HSM.

- [Keystone](https://keystone-enclave.org) - Open-source project for building trusted execution environments (TEE) with secure hardware enclaves, based on the RISC-V architecture.

- [Project Oak](https://github.com/project-oak/oak) - A specification and a reference implementation for the secure transfer, storage and processing of data.

- [Everybody be cool, this is a robbery!](https://www.sstic.org/2019/presentation/hsm/) - A case study of vulnerability and exploitability of a HSM (in French, sorry).

## Trust & Safety

Once you've got a significant user base, it is called a community. You'll then be responsible to protect it: the customer, people, the company, the business, and facilitate all interactions and transactions happening therein.

A critical intermediation complex driven by a policy and constraint by local laws, the Trust & Safety department is likely embodied by a cross-functional team of 24/7 operators and systems of highly advanced moderation and administration tools. You can see it as an extension of customer support services, specialized in edge-cases like manual identity checks, moderation of harmful content, stopping harassment, handling of warrants and copyright claims, data sequestration and other credit card disputes.

- [Trust and safety 101](https://www.csoonline.com/article/3206127/trust-and-safety-101.html) - A great introduction on the domain and its responsibilities.

- [What the Heck is Trust and Safety?](https://www.linkedin.com/pulse/what-heck-trust-safety-kenny-shi) - A couple of real use-case to demonstrate the role of a TnS team.

<!--lint disable double-link-->

- [Awesome List of Billing and Payments: Fraud links](https://github.com/kdeldycke/awesome-billing#fraud) - Section dedicated to fraud management for billing and payment, from our sister repository.

<!--lint enable double-link-->

### User Identity

Most businesses do not collect customer's identity to create user profiles to sell to third party, no. But you still have to: local laws require to keep track of contract relationships under the large [Know You Customer (KYC)](https://en.wikipedia.org/wiki/Know_your_customer) banner.

- [The Laws of Identity](https://www.identityblog.com/stories/2005/05/13/TheLawsOfIdentity.pdf) - Is this paper aims at identity metasystem, its laws still provides great insights at smaller scale, especially the first law: to always allow user control and ask for consent to earn trust.

- [How Uber Got Lost](https://archive.ph/hvjKl) - “To limit "friction" Uber allowed riders to sign up without requiring them to provide identity beyond an email — easily faked — or a phone number. (…) Vehicles were stolen and burned; drivers were assaulted, robbed and occasionally murdered. The company stuck with the low-friction sign-up system, even as violence increased.”

- [A Comparison of Personal Name Matching: Techniques and Practical Issues](http://users.cecs.anu.edu.au/~Peter.Christen/publications/tr-cs-06-02.pdf) - Customer name matching has lots of application, from account deduplication to fraud monitoring.

- [Statistically Likely Usernames](https://github.com/insidetrust/statistically-likely-usernames) - Wordlists for creating statistically likely usernames for use in username-enumeration, simulated password-attacks and other security testing tasks.

- [Facebook Dangerous Individuals and Organizations List](https://theintercept.com/document/facebook-dangerous-individuals-and-organizations-list-reproduced-snapshot/) - Some groups and content are illegal in some juridictions. This is an example of a blocklist.

- [Ballerine](https://github.com/ballerine-io/ballerine) - An open-source infrastructure for user identity and risk management.

- [Sherlock](https://github.com/sherlock-project/sherlock) - Hunt down social media accounts by username across social networks.

### Fraud

As an online service provider, you're exposed to fraud, crime and abuses. You'll be surprised by how much people gets clever when it comes to money. Expect any bug or discrepancies in your workflow to be exploited for financial gain.

- [After Car2Go eased its background checks, 75 of its vehicles were stolen in one day.](https://web.archive.org/web/20230526073109/https://www.bloomberg.com/news/articles/2019-07-11/mercedes-thieves-showed-just-how-vulnerable-car-sharing-can-be) - Why background check are sometimes necessary.

- [Investigation into the Unusual Signups](https://openstreetmap.lu/MWGGlobalLogicReport20181226.pdf) - A really detailed analysis of suspicious contributor signups on OpenStreetMap. This beautiful and high-level report demonstrating an orchestrated and directed campaign might serve as a template for fraud reports.

- [MIDAS: Detecting Microcluster Anomalies in Edge Streams](https://github.com/bhatiasiddharth/MIDAS) - A proposed method to “detects microcluster anomalies, or suddenly arriving groups of suspiciously similar edges, in edge streams, using constant time and memory.”

- [Gephi](https://github.com/gephi/gephi) - Open-source platform for visualizing and manipulating large graphs.

### Moderation

Any online communities, not only those related to gaming and social networks, requires their operator to invest a lot of resource and energy to moderate it.

- [Still Logged In: What AR and VR Can Learn from MMOs](https://youtu.be/kgw8RLHv1j4?t=534) - “If you host an online community, where people can harm another person: you are on the hook. And if you can't afford to be on the hook, don't host an online community”.

- [You either die an MVP or live long enough to build content moderation](https://mux.com/blog/you-either-die-an-mvp-or-live-long-enough-to-build-content-moderation/) - “You can think about the solution space for this problem by considering three dimensions: cost, accuracy and speed. And two approaches: human review and machine review. Humans are great in one of these dimensions: accuracy. The downside is that humans are expensive and slow. Machines, or robots, are great at the other two dimensions: cost and speed - they're much cheaper and faster. But the goal is to find a robot solution that is also sufficiently accurate for your needs.”

- [The despair and darkness of people will get to you](https://restofworld.org/2020/facebook-international-content-moderators/) - Moderation of huge social networks is performed by an army of outsourced subcontractors. These people are exposed to the worst and generally ends up with PTSD.

- [The Cleaners](https://thoughtmaybe.com/the-cleaners/) - A documentary on these teams of underpaid people removing posts and deleting accounts.

### Threat Intelligence

How to detect, unmask and classify offensive online activities. Most of the time these are monitored by security, networking and/or infrastructure engineering teams. Still, these are good resources for T&S and IAM people, who might be called upon for additional expertise for analysis and handling of threats.

- [Awesome Threat Intelligence](https://github.com/hslatman/awesome-threat-intelligence) - “A concise definition of Threat Intelligence: evidence-based knowledge, including context, mechanisms, indicators, implications and actionable advice, about an existing or emerging menace or hazard to assets that can be used to inform decisions regarding the subject's response to that menace or hazard.”

- [SpiderFoot](https://github.com/smicallef/spiderfoot) - An open source intelligence (OSINT) automation tool. It integrates with just about every data source available and uses a range of methods for data analysis, making that data easy to navigate.

- [Standards related to Threat Intelligence](https://www.threat-intelligence.eu/standards/) - Open standards, tools and methodologies to support threat intelligence analysis.

- [MISP taxonomies and classification](https://www.misp-project.org/taxonomies.html) - Tags to organize information on “threat intelligence including cyber security indicators, financial fraud or counter-terrorism information.”

- [Browser Fingerprinting: A survey](https://arxiv.org/pdf/1905.01051.pdf) - Fingerprints can be used as a source of signals to identify bots and fraudsters.

- [The challenges of file formats](https://speakerdeck.com/ange/the-challenges-of-file-formats) - At one point you will let users upload files in your system. Here is a [corpus of suspicious media files](https://github.com/corkami/pocs) that can be leveraged by scammers =to bypass security or fool users.

- [SecLists](https://github.com/danielmiessler/SecLists) - Collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more.

- [PhishingKitTracker](https://github.com/neonprimetime/PhishingKitTracker) - CSV database of email addresses used by threat actor in phishing kits.

- [PhoneInfoga](https://github.com/sundowndev/PhoneInfoga) - Tools to scan phone numbers using only free resources. The goal is to first gather standard information such as country, area, carrier and line type on any international phone numbers with a very good accuracy. Then search for footprints on search engines to try to find the VoIP provider or identify the owner.

- [Confusable Homoglyphs](https://github.com/vhf/confusable_homoglyphs) - Homoglyphs is a common phishing trick.

### Captcha

Another line of defense against spammers.

- [Awesome Captcha](https://github.com/ZYSzys/awesome-captcha) - Reference all open-source captcha libraries, integration, alternatives and cracking tools.

- [reCaptcha](https://www.google.com/recaptcha) - reCaptcha is still an effective, economical and quick solution when your company can't afford to have a dedicated team to fight bots and spammers at internet scale.

- [You (probably) don't need ReCAPTCHA](https://web.archive.org/web/20190611190134/https://kevv.net/you-probably-dont-need-recaptcha/) - Starts with a rant on how the service is a privacy nightmare and is tedious UI-wise, then list alternatives.

- [Anti-captcha](https://anti-captcha.com) - Captchas solving service.

## Blocklists

The first mechanical line of defense against abuses consist in plain and simple deny-listing. This is the low-hanging fruit of fraud fighting, but you'll be surprised how they're still effective.

- [Bloom Filter](https://en.wikipedia.org/wiki/Bloom_filter) - Perfect for this use-case, as bloom filters are designed to quickly check if an element is not in a (large) set. Variations of bloom filters exist for specific data types.

- [How Radix trees made blocking IPs 5000 times faster](https://blog.sqreen.com/demystifying-radix-trees/) - Radix trees might come handy to speed-up IP blocklists.

### Hostnames and Subdomains

Useful to identified clients, catch and block swarms of bots, and limit effects of dDOS.

- [`hosts`](https://github.com/StevenBlack/hosts) - Consolidates reputable hosts files, and merges them into a unified hosts file with duplicates removed.

- [`nextdns/metadata`](https://github.com/nextdns/metadata) - Extensive collection of list for security, privacy and parental control.

- [The Public Suffix List](https://publicsuffix.org) - Mozilla's registry of public suffixes, under which Internet users can (or historically could) directly register names.

- [Country IP Blocks](https://github.com/herrbischoff/country-ip-blocks) - CIDR country-level IP data, straight from the Regional Internet Registries, updated hourly.

- [Certificate Transparency Subdomains](https://github.com/internetwache/CT_subdomains) - An hourly updated list of subdomains gathered from certificate transparency logs.

- Subdomain denylists: [#1](https://gist.github.com/artgon/5366868), [#2](https://github.com/sandeepshetty/subdomain-blacklist/blob/master/subdomain-blacklist.txt), [#3](https://github.com/nccgroup/typofinder/blob/master/TypoMagic/datasources/subdomains.txt), [#4](https://www.quora.com/How-do-sites-prevent-vanity-URLs-from-colliding-with-future-features).

- [`common-domain-prefix-suffix-list.tsv`](https://gist.github.com/erikig/826f49442929e9ecfab6d7c481870700) - Top-5000 most common domain prefix/suffix list.

- [`hosts-blocklists`](https://github.com/notracking/hosts-blocklists) - No more ads, tracking and other virtual garbage.

- [`xkeyscorerules100.txt`](https://gist.github.com/sehrgut/324626fa370f044dbca7) - NSA's [XKeyscore](https://en.wikipedia.org/wiki/XKeyscore) matching rules for TOR and other anonymity preserving tools.

- [`pyisp`](https://github.com/ActivisionGameScience/pyisp) - IP to ISP lookup library (includes ASN).

- [AMF site blocklist](https://www.amf-france.org/Epargne-Info-Service/Proteger-son-epargne/Listes-noires) - Official French denylist of money-related fraud sites.

### Emails

- [Burner email providers](https://github.com/wesbos/burner-email-providers) - A list of temporary email providers. And its [derivative Python module](https://github.com/martenson/disposable-email-domains).

- [MailChecker](https://github.com/FGRibreau/mailchecker) - Cross-language temporary (disposable/throwaway) email detection library.

- [Temporary Email Address Domains](https://gist.github.com/adamloving/4401361) - A list of domains for disposable and temporary email addresses. Useful for filtering your email list to increase open rates (sending email to these domains likely will not be opened).

- [`gman`](https://github.com/benbalter/gman) - “A ruby gem to check if the owner of a given email address or website is working for THE MAN (a.k.a verifies government domains).” Good resource to hunt for potential government customers in your user base.

- [`Swot`](https://github.com/leereilly/swot) - In the same spirit as above, but this time to flag academic users.

### Reserved IDs

- [General List of Reserved Words](https://gist.github.com/stuartpb/5710271) - This is a general list of words you may want to consider reserving, in a system where users can pick any name.

- [Hostnames and usernames to reserve](https://ldpreload.com/blog/names-to-reserve) - List of all the names that should be restricted from registration in automated systems.

### Profanity

- [List of Dirty, Naughty, Obscene, and Otherwise Bad Words](https://github.com/LDNOOBW/List-of-Dirty-Naughty-Obscene-and-Otherwise-Bad-Words) - Profanity blocklist from Shutterstock.

- [`profanity-check`](https://github.com/vzhou842/profanity-check) - Uses a linear SVM model trained on 200k human-labeled samples of clean and profane text strings.

## Privacy

As the guardian of user's data, the IAM stack is deeply bounded by the respect of privacy.

- [Privacy Enhancing Technologies Decision Tree](https://www.private-ai.com/wp-content/uploads/2021/10/PETs-Decision-Tree.pdf) - A flowchart to select the right tool depending on data type and context.

- [Paper we love: Privacy](https://github.com/papers-we-love/papers-we-love/tree/master/privacy) - A collection of scientific studies of schemes providing privacy by design.

- [Have I been Pwned?](https://haveibeenpwned.com) - Data breach index.

- [Automated security testing for Software Developers](https://fahrplan.events.ccc.de/camp/2019/Fahrplan/system/event_attachments/attachments/000/003/798/original/security_cccamp.pdf) - Most privacy breaches were allowed by known vulnerabilities in third-party dependencies. Here is how to detect them by the way of CI/CD.

- [Email marketing regulations around the world](https://github.com/threeheartsdigital/email-marketing-regulations) - As the world becomes increasingly connected, the email marketing regulation landscape becomes more and more complex.

- [World's Biggest Data Breaches & Hacks](https://www.informationisbeautiful.net/visualizations/worlds-biggest-data-breaches-hacks/) - Don't be the next company leaking your customer's data.

### Anonymization

As a central repository of user data, the IAM stack stakeholders have to prevent any leakage of business and customer data. To allow for internal analytics, anonymization is required.

- [The False Allure of Hashing for Anonymization](https://web.archive.org/web/20220927004103/https://goteleport.com/blog/hashing-for-anonymization/) - Hashing is not sufficient for anonymization no. But still it is good enough for pseudonymization (which is allowed by the GDPR).

- [Four cents to deanonymize: Companies reverse hashed email addresses](https://freedom-to-tinker.com/2018/04/09/four-cents-to-deanonymize-companies-reverse-hashed-email-addresses/) - “Hashed email addresses can be easily reversed and linked to an individual”.

- [Why differential privacy is awesome](https://desfontain.es/privacy/differential-privacy-awesomeness.html) - Explain the intuition behind [differential privacy](https://en.wikipedia.org/wiki/Differential_privacy), a theoretical framework which allow sharing of aggregated data without compromising confidentiality. See follow-up articles with [more details](https://desfontain.es/privacy/differential-privacy-in-more-detail.html) and [practical aspects](https://desfontain.es/privacy/differential-privacy-in-practice.html).

- [k-anonymity: an introduction](https://www.privitar.com/listing/k-anonymity-an-introduction) - An alternative anonymity privacy model.

- [Presidio](https://github.com/microsoft/presidio) - Context aware, pluggable and customizable data protection and PII data anonymization service for text and images.

- [Diffix: High-Utility Database Anonymization](https://aircloak.com/wp-content/uploads/apf17-aspen.pdf) - Diffix try to provide anonymization, avoid pseudonymization and preserve data quality. [Written in Elixir at Aircloak](https://elixirforum.com/t/aircloak-anonymized-analitycs/10930), it acts as an SQL proxy between the analyst and an unmodified live database.

### GDPR

The well-known European privacy framework

- [GDPR Tracker](https://gdpr.eu) - Europe's reference site.

- [GDPR Developer Guide](https://github.com/LINCnil/GDPR-Developer-Guide) - Best practices for developers.

- [GDPR – A Practical guide for Developers](https://techblog.bozho.net/gdpr-practical-guide-developers/) - A one-page summary of the above.

- [GDPR documents](https://github.com/good-lly/gdpr-documents) - Templates for personal use to have companies comply with "Data Access" requests.

- [Dark Patterns after the GDPR](https://arxiv.org/pdf/2001.02479.pdf) - This paper demonstrates that, because of the lack of GDPR law enforcements, dark patterns and implied consent are ubiquitous.

- [GDPR Enforcement Tracker](http://enforcementtracker.com) - List of GDPR fines and penalties.

## UX/UI

As stakeholder of the IAM stack, you're going to implement in the backend the majority of the primitives required to build-up the sign-up tunnel and user onboarding. This is the first impression customers will get from your product, and can't be overlooked: you'll have to carefully design it with front-end experts. Here is a couple of guides to help you polish that experience.

- [The 2020 State of SaaS Product Onboarding](https://userpilot.com/saas-product-onboarding/) - Covers all the important facets of user onboarding.

- [User Onboarding Teardowns](https://www.useronboard.com/user-onboarding-teardowns/) - A huge list of deconstructed first-time user signups.

- [Discover UI Design Decisions Of Leading Companies](https://goodui.org/leaks/) - From Leaked Screenshots & A/B Tests.

- [Conversion Optimization](https://www.nickkolenda.com/conversion-optimization-psychology/#cro-tactic11) - A collection of tactics to increase the chance of users finishing the account creation funnel.

- [Trello User Onboarding](https://growth.design/case-studies/trello-user-onboarding/) - A detailed case study, nicely presented, on how to improve user onboarding.

- [11 Tips for Better Signup / Login UX](https://learnui.design/blog/tips-signup-login-ux.html) - Some basic tips on the login form.

- [Don't get clever with login forms](http://bradfrost.com/blog/post/dont-get-clever-with-login-forms/) - Create login forms that are simple, linkable, predictable, and play nicely with password managers.

- [Why are the username and password on two different pages?](https://www.twilio.com/blog/why-username-and-password-on-two-different-pages) - To support both SSO and password-based login. Now if breaking the login funnel in 2 steps is too infuriating to users, solve this as Dropbox does: [an AJAX request when you enter your username](https://news.ycombinator.com/item?id=19174355).

- [HTML attributes to improve your users' two factor authentication experience](https://www.twilio.com/blog/html-attributes-two-factor-authentication-autocomplete) - “In this post we will look at the humble `<input>` element and the HTML attributes that will help speed up our users' two factor authentication experience”.

- [Remove password masking](http://passwordmasking.com) - Summarizes the results from an academic study investigating the impact removing password masking has on consumer trust.

- [For anybody who thinks "I could build that in a weekend," this is how Slack decides to send a notification](https://twitter.com/ProductHunt/status/979912670970249221) - Notifications are hard. Really hard.

## Competitive Analysis

Keep track on the activity of open-source projects and companies operating in the domain.

- [Best-of Digital Identity](https://github.com/jruizaranguren/best-of-digital-identity) - Ranking, popularity and activity status of open-source digital identity projects.

- [AWS Security, Identity & Compliance announcements](https://aws.amazon.com/about-aws/whats-new/security_identity_and_compliance/) - The source of all new features added to the IAM perimeter.

- [GCP IAM release notes](https://cloud.google.com/iam/docs/release-notes) - Also of note: [Identity](https://cloud.google.com/identity/docs/release-notes), [Identity Platform](https://cloud.google.com/identity-platform/docs/release-notes), [Resource Manager](https://cloud.google.com/resource-manager/docs/release-notes), [Key Management Service/HSM](https://cloud.google.com/kms/docs/release-notes), [Access Context Manager](https://cloud.google.com/access-context-manager/docs/release-notes), [Identity-Aware Proxy](https://cloud.google.com/iap/docs/release-notes), [Data Loss Prevention](https://cloud.google.com/dlp/docs/release-notes) and [Security Scanner](https://cloud.google.com/security-scanner/docs/release-notes).

- [Unofficial Weekly Google Cloud Platform newsletter](https://www.gcpweekly.com) - Relevant keywords: [`IAM`](https://www.gcpweekly.com/gcp-resources/tag/iam/) and [`Security`](https://www.gcpweekly.com/gcp-resources/tag/security/).

- [DigitalOcean Accounts changelog](http://docs.digitalocean.com/release-notes/accounts/) - All the latest accounts updates on DO.

- [163 AWS services explained in one line each](https://adayinthelifeof.nl/2020/05/20/aws.html#discovering-aws) - Help makes sense of their huge service catalog. In the same spirit: [AWS in simple terms](https://netrixllc.com/blog/aws-services-in-simple-terms/) & [AWS In Plain English](https://expeditedsecurity.com/aws-in-plain-english/).

- [Google Cloud Developer's Cheat Sheet](https://github.com/gregsramblings/google-cloud-4-words#the-google-cloud-developers-cheat-sheet) - Describe all GCP products in 4 words or less.

## History

- [cryptoanarchy.wiki](https://cryptoanarchy.wiki) - Cypherpunks overlaps with security. This wiki compiles information about the movement, its history and the people/events of note.

## Contributing

Your contributions are always welcome! Please take a look at the [contribution guidelines](.github/contributing.md) first.

## Footnotes

The [header image](https://github.com/kdeldycke/awesome-iam/blob/main/assets/awesome-iam-header.jpg) is based on a modified [photo](https://unsplash.com/photos/2LowviVHZ-E) by [Ben Sweet](https://unsplash.com/@benjaminsweet).

<!--lint disable no-undefined-references-->

<a name="sponsor-def">[0]</a>: You can <a href="https://github.com/sponsors/kdeldycke">add your Identity & Authentication product in the list of sponsors via a GitHub sponsorship</a>. [[↑]](#sponsor-ref)

<a name="intro-quote-def">[1]</a>: [*Poison Study*](https://www.amazon.com/dp/0778324338?&linkCode=ll1&tag=kevideld-20&linkId=0b92c3d92371bd53daca5457bdad327e&language=en_US&ref_=as_li_ss_tl) (Mira, 2007). [[↑]](#intro-quote-ref)
