# Awesome Identity and Access Management


## Meta

* [IAM definition](https://en.wikipedia.org/wiki/Identity_management)


## Authorization, ACLs

* [Zanzibar: Google’s Consistent, Global Authorization System](https://ai.google/research/pubs/pub48190) - scales to
trillions of access control lists and millions of authorization requests per second to support services used by
billions of people. It has maintained 95th-percentile latency of less than 10 milliseconds and availability of
greater than 99.999% over 3 years of production use. [Other bits not in the paper](https://twitter.com/LeaKissner/status/1136626971566149633).


## Multi-Factor Authentication

* [Beyond Passwords: 2FA, U2F and Google Advanced Protection](https://www.troyhunt.com/beyond-passwords-2fa-u2f-and-google-advanced-protection/) - An excellent walk-trough over all these technologies.
* [A Comparative Long-Term Study of Fallback Authentication](https://www.mobsec.ruhr-uni-bochum.de/media/mobsec/veroeffentlichungen/2019/02/20/usec2019-30-wip-fallback-long-term-study-finalv2.pdf) - Key take-away: `schemes based on email and SMS are more usable. Mechanisms based on designated trustees and personal knowledge questions, on the other hand, fall short, both in terms of convenience and efficiency.`
* [How effective is basic account hygiene at preventing hijacking](https://security.googleblog.com/2019/05/new-research-how-effective-is-basic.html) - Data shows 2FA blocks 100% of automated bot hacks.
* [webauthn and security keys](https://www.imperialviolet.org/2018/03/27/webauthn.html)
* [Attacking Google Authenticator](https://unix-ninja.com/p/attacking_google_authenticator) - Probably on the verge of paranoia, but might be a reason to rate limit 2FA validation attempts.
* [Compromising online accounts by cracking voicemail systems](https://www.martinvigo.com/voicemailcracker/) - Or why you should not rely on automated phone calls as a method to reach the user and reset passwords, 2FA or for any kind of verification. Not unlike SMS-based 2FA, it is currently insecure and can be compromised by the way of its weakest link: voicemail systems.


## Passwords

* [An argument for passwordless](https://biarity.gitlab.io/2018/02/23/passwordless/)
* [Password expiration is dead](https://techcrunch.com/2019/06/02/password-expiration-is-dead-long-live-your-passwords/) - Recent scientific research calls into question the value of many long-standing password-security practices such as password expiration policies, and points instead to better alternatives such as enforcing banned-password lists and MFA.


## Public-Key Infrastructure (PKI)

* [PKI for busy people](https://rehn.me/posts/pki-for-busy-people.html) - Quick overview of the important stuff.


## Open-Source Projects

* [Keycloak](https://www.keycloak.org)
* [Cierge](https://pwdless.github.io/Cierge-Website/)
* [ORY](https://www.ory.sh)
* [Open Policy Agent](https://github.com/open-policy-agent/opa)
* [Casbin](https://github.com/casbin/casbin)
