# Awesome Identity and Access Management


## Meta

* [IAM definition](https://en.wikipedia.org/wiki/Identity_management)


## Authorization, ACLs

* [Zanzibar: Google’s Consistent, Global Authorization System](https://ai.google/research/pubs/pub48190) - scales to
trillions of access control lists and millions of authorization requests per second to support services used by
billions of people. It has maintained 95th-percentile latency of less than 10 milliseconds and availability of
greater than 99.999% over 3 years of production use. [Other bits not in the paper](https://twitter.com/LeaKissner/status/1136626971566149633).
* [Role Based Access Control](https://csrc.nist.gov/projects/role-based-access-control)


## OAuth2

* [OAuth 2 Simplified](https://aaronparecki.com/oauth-2-simplified/) - A reference article describing the protocol in simplified format to help developers and service providers implement it.


## Multi-Factor Authentication

* [Beyond Passwords: 2FA, U2F and Google Advanced Protection](https://www.troyhunt.com/beyond-passwords-2fa-u2f-and-google-advanced-protection/) - An excellent walk-trough over all these technologies.
* [A Comparative Long-Term Study of Fallback Authentication](https://www.mobsec.ruhr-uni-bochum.de/media/mobsec/veroeffentlichungen/2019/02/20/usec2019-30-wip-fallback-long-term-study-finalv2.pdf) - Key take-away: `schemes based on email and SMS are more usable. Mechanisms based on designated trustees and personal knowledge questions, on the other hand, fall short, both in terms of convenience and efficiency.`
* [How effective is basic account hygiene at preventing hijacking](https://security.googleblog.com/2019/05/new-research-how-effective-is-basic.html) - Data shows 2FA blocks 100% of automated bot hacks.
* [Webauthn and security keys](https://www.imperialviolet.org/2018/03/27/webauthn.html)
* [Attacking Google Authenticator](https://unix-ninja.com/p/attacking_google_authenticator) - Probably on the verge of paranoia, but might be a reason to rate limit 2FA validation attempts.
* [Compromising online accounts by cracking voicemail systems](https://www.martinvigo.com/voicemailcracker/) - Or why you should not rely on automated phone calls as a method to reach the user and reset passwords, 2FA or for any kind of verification. Not unlike SMS-based 2FA, it is currently insecure and can be compromised by the way of its weakest link: voicemail systems.
* [Getting 2FA Right in 2019](https://blog.trailofbits.com/2019/06/20/getting-2fa-right-in-2019/) - On the UX aspects of 2FA.


## SMS-based Authentication

* [SMS 2FA auth is deprecated by NIST](https://techcrunch.com/2016/07/25/nist-declares-the-age-of-sms-based-2-factor-authentication-over/)
* [SMS: The most popular and least secure 2FA method](https://www.allthingsauth.com/2018/02/27/sms-the-most-popular-and-least-secure-2fa-method/)
* [AT&T rep handed control of his cellphone account to a hacker](https://www.theregister.co.uk/2017/07/10/att_falls_for_hacker_tricks/)
* [The Most Expensive Lesson Of My Life: Details of SIM port hack](https://medium.com/coinmonks/the-most-expensive-lesson-of-my-life-details-of-sim-port-hack-35de11517124)
* [SIM swap horror story](https://www.zdnet.com/article/sim-swap-horror-story-ive-lost-decades-of-data-and-google-wont-lift-a-finger/)
* [AWS is on its way to deprecate SMS-based 2FA](https://aws.amazon.com/iam/details/mfa/) - `We encourage you to use MFA through a U2F security key, hardware device, or virtual (software-based) MFA device. You can continue using this feature until January 31, 2019.`


## Passwords

* [An argument for passwordless](https://biarity.gitlab.io/2018/02/23/passwordless/)
* [Password expiration is dead](https://techcrunch.com/2019/06/02/password-expiration-is-dead-long-live-your-passwords/) - Recent scientific research calls into question the value of many long-standing password-security practices such as password expiration policies, and points instead to better alternatives such as enforcing banned-password lists and MFA.


## Public-Key Infrastructure (PKI)

* [PKI for busy people](https://rehn.me/posts/pki-for-busy-people.html) - Quick overview of the important stuff.


## UX/UI

* [Don’t get clever with login forms](http://bradfrost.com/blog/post/dont-get-clever-with-login-forms/) - TL;DR; create login forms that are simple, linkable, predictable, and play nicely with password managers.
* [Why are the username and password on two different pages?](https://www.twilio.com/blog/why-username-and-password-on-two-different-pages) - TL;DR: to support both SSO and password-based login.


## Identity

* [Hostnames and usernames to reserve](https://ldpreload.com/blog/names-to-reserve)


## Captcha

* [Anti-captcha](https://anti-captcha.com) - Captchas solving service


## Privacy

* [IRMA Authentication](https://news.ycombinator.com/item?id=20144240) - Open-source app and protocol that offers privacy-friendly attribute based authentication and signing using [Camenisch and Lysyanskaya's Idemix](https://privacybydesign.foundation/publications/).


## Open-Source Projects

* [Keycloak](https://www.keycloak.org)
* [Cierge](https://pwdless.github.io/Cierge-Website/)
* [ORY](https://www.ory.sh): [Hydra](https://github.com/ory/hydra)
* [Open Policy Agent](https://github.com/open-policy-agent/opa)
* [Casbin](https://github.com/casbin/casbin)
* [IdentityServer](https://identityserver.io)
* [gluu](https://www.gluu.org)
