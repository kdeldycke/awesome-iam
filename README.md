# Awesome Identity and Access Management

In a [Cloud computing overview Standford class](http://web.stanford.edu/class/cs349d/docs/L01_overview.pdf), the cloud software stack is presented as such:

![](cloud-software-stack-iam.png)

This knowledge base cover the far right perimeter of the cloud stack.


## Meta

* [IAM definition](https://en.wikipedia.org/wiki/Identity_management)


## Password-based Authentication

* [Password expiration is dead](https://techcrunch.com/2019/06/02/password-expiration-is-dead-long-live-your-passwords/) - Recent scientific research calls into question the value of many long-standing password-security practices such as password expiration policies, and points instead to better alternatives such as enforcing banned-password lists and MFA.


## Password-less Authentication

* [An argument for passwordless](https://biarity.gitlab.io/2018/02/23/passwordless/) - Passwords are not the be-all and end-all of user authentication. This article ties to tell you why.
* [Webauthn and security keys](https://www.imperialviolet.org/2018/03/27/webauthn.html) - WebAuthn is a replacement for password authentication.


## Multi-Factor Authentication

* [Beyond Passwords: 2FA, U2F and Google Advanced Protection](https://www.troyhunt.com/beyond-passwords-2fa-u2f-and-google-advanced-protection/) - An excellent walk-trough over all these technologies.
* [A Comparative Long-Term Study of Fallback Authentication](https://www.mobsec.ruhr-uni-bochum.de/media/mobsec/veroeffentlichungen/2019/02/20/usec2019-30-wip-fallback-long-term-study-finalv2.pdf) - Key take-away: `schemes based on email and SMS are more usable. Mechanisms based on designated trustees and personal knowledge questions, on the other hand, fall short, both in terms of convenience and efficiency.`
* [How effective is basic account hygiene at preventing hijacking](https://security.googleblog.com/2019/05/new-research-how-effective-is-basic.html) - Data shows 2FA blocks 100% of automated bot hacks.
* [Attacking Google Authenticator](https://unix-ninja.com/p/attacking_google_authenticator) - Probably on the verge of paranoia, but might be a reason to rate limit 2FA validation attempts.
* [Compromising online accounts by cracking voicemail systems](https://www.martinvigo.com/voicemailcracker/) - Or why you should not rely on automated phone calls as a method to reach the user and reset passwords, 2FA or for any kind of verification. Not unlike SMS-based 2FA, it is currently insecure and can be compromised by the way of its weakest link: voicemail systems.
* [Getting 2FA Right in 2019](https://blog.trailofbits.com/2019/06/20/getting-2fa-right-in-2019/) - On the UX aspects of 2FA.


## SMS-based Authentication

TL;DR: don't. For details, see articles below.

* [SMS 2FA auth is deprecated by NIST](https://techcrunch.com/2016/07/25/nist-declares-the-age-of-sms-based-2-factor-authentication-over/)
* [SMS: The most popular and least secure 2FA method](https://www.allthingsauth.com/2018/02/27/sms-the-most-popular-and-least-secure-2fa-method/)
* [AT&T rep handed control of his cellphone account to a hacker](https://www.theregister.co.uk/2017/07/10/att_falls_for_hacker_tricks/)
* [The Most Expensive Lesson Of My Life: Details of SIM port hack](https://medium.com/coinmonks/the-most-expensive-lesson-of-my-life-details-of-sim-port-hack-35de11517124)
* [SIM swap horror story](https://www.zdnet.com/article/sim-swap-horror-story-ive-lost-decades-of-data-and-google-wont-lift-a-finger/)
* [AWS is on its way to deprecate SMS-based 2FA](https://aws.amazon.com/iam/details/mfa/) - `We encourage you to use MFA through a U2F security key, hardware device, or virtual (software-based) MFA device. You can continue using this feature until January 31, 2019.`


## Authorization, ACL and RBAC

All things related to access control policies, from classic [Access Control Lists](https://en.wikipedia.org/wiki/Access-control_list) to [Role Based Access Control](https://en.wikipedia.org/wiki/Role-based_access_control).

* [Zanzibar: Google’s Consistent, Global Authorization System](https://ai.google/research/pubs/pub48190) - scales to
trillions of access control lists and millions of authorization requests per second to support services used by
billions of people. It has maintained 95th-percentile latency of less than 10 milliseconds and availability of
greater than 99.999% over 3 years of production use. [Other bits not in the paper](https://twitter.com/LeaKissner/status/1136626971566149633).
* [Role Based Access Control](https://csrc.nist.gov/projects/role-based-access-control) - NIST project to explaine RBAC concepts, costs and benefits, the economic impact of RBAC, design and implementation issues, the RBAC standard, and advanced research topics.
* [keto](https://github.com/ory/keto) - Policy decision point. It uses a set of access control policies, similar to AWS IAM Policies, in order to determine whether a subject is authorized to perform a certain action on a resource.
* [ladon](https://github.com/ory/ladon) - Access control library, inspired by [AWS IAM Policies](http://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html).


## Zero-trust Network

Zero trust network security operates under the principle “never trust, always verify.”.

* [BeyondCorp - A New Approach to Enterprise Security](https://www.usenix.org/system/files/login/articles/login_dec14_02_ward.pdf) - Quick overview of Google’s Zero-trust Network initiative.
* [oathkeeper](https://github.com/ory/oathkeeper) - Identity & Access Proxy and Access Control Decision API that authenticates, authorizes, and mutates incoming HTTP requests. Inspired by the BeyondCorp / Zero Trust white paper.
* [transcend](https://github.com/cogolabs/transcend) - BeyondCorp-inspired Access Proxy server.


## OAuth2 & OpenID

* [OAuth 2 Simplified](https://aaronparecki.com/oauth-2-simplified/) - A reference article describing the protocol in simplified format to help developers and service providers implement it.
* [Hydra](https://gethydra.sh) - Open-source OpenID Connect & OAuth2 Server.


## Public-Key Infrastructure (PKI)

* [PKI for busy people](https://rehn.me/posts/pki-for-busy-people.html) - Quick overview of the important stuff.


## JWT

[JSON Web Token](https://en.wikipedia.org/wiki/JSON_Web_Token) is a kind of bearer's token.

* [Introduction to JSON Web Tokens](https://jwt.io/introduction/) - Get up to speed on JWT with this article.
* [Using JSON Web Tokens as API Keys](https://auth0.com/blog/using-json-web-tokens-as-api-keys/) - Compared to API keys, JWTs offers granular security, homogenous auth architecture, decentralized issuance, OAuth2 compliance, debuggability, expiration control, device management.
* [Blacklisting JSON Web Token API Keys](https://auth0.com/blog/blacklist-json-web-token-api-keys/) - On token invalidation.
* [Stop using JWT for sessions](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/), and [Why your "solution" doesn't work](http://cryto.net/%7Ejoepie91/blog/2016/06/19/stop-using-jwt-for-sessions-part-2-why-your-solution-doesnt-work/) - Stateless JWT tokens cannot be invalidated or updated, and will introduce either size issues or security issues depending on where you store them. Stateful JWT tokens are functionally the same as session cookies, but without the battle-tested and well-reviewed implementations or client support. 
* [JWT.IO](https://jwt.io) - Allows you to decode, verify and generate JWT.


## Macaroons

A clever curiosity to distribute authorization.

* [Google's Macaroons in Five Minutes or Less](https://blog.bren2010.io/2014/12/04/macaroons.html) - TL;DR: if I’m given a Macaroon that authorizes me to perform some action(s) under certain restrictions, I can non-interactively build a second Macaroon with stricter restrictions that I can then give to you.
* [Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud](https://ai.google/research/pubs/pub41892) - Google's original paper.
* [Google paper's author compares Macaroons and JWTs](https://news.ycombinator.com/item?id=14294463) - TL;DR: As a consumer/verifier of macaroons, they allow you (through third-party caveats) to defer some authorization decisions to someone else. JWTs don't.


## User Identity

On managing users and their metadata.

* [hive](https://github.com/ory/hive) - User & Identity Provider & Management.
* [Hostnames and usernames to reserve](https://ldpreload.com/blog/names-to-reserve)


## Fraud

Managing users expose services and businesses to fraud, crime, abuses, trust and safety. You should never underestimate how much cleverer than you people will be when it comes to money.

* [After Car2Go eased its background checks, 75 of its vehicles were stolen in one day.](https://archive.is/MuNrZ) - Why background check are sometimes necessary.


## Captcha

* [Anti-captcha](https://anti-captcha.com) - Captchas solving service.


## Privacy

* [IRMA Authentication](https://news.ycombinator.com/item?id=20144240) - Open-source app and protocol that offers privacy-friendly attribute based authentication and signing using [Camenisch and Lysyanskaya's Idemix](https://privacybydesign.foundation/publications/).


## UX/UI

* [Don’t get clever with login forms](http://bradfrost.com/blog/post/dont-get-clever-with-login-forms/) - TL;DR; create login forms that are simple, linkable, predictable, and play nicely with password managers.
* [Why are the username and password on two different pages?](https://www.twilio.com/blog/why-username-and-password-on-two-different-pages) - TL;DR: to support both SSO and password-based login.


## Open-Source Projects

* [Keycloak](https://www.keycloak.org) - Open Source Identity and Access Management.
* [Cierge](https://pwdless.github.io/Cierge-Website/) - Open source authentication server (OIDC) that handles user signup, login, profiles, management, and more.
* [Open Policy Agent](https://github.com/open-policy-agent/opa)
* [Casbin](https://github.com/casbin/casbin)
* [IdentityServer](https://identityserver.io)
* [gluu](https://www.gluu.org)
