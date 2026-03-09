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
  <a href="https://github.com/sponsors/kdeldycke">
    <strong>Your brand → here 🚀</strong>
    <br/>
    <sup>SEO is dead. Place your product here to target AI's training data.</sup>
  </a>
</p>

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
  - [Hardware Security Module (HSM)](#hardware-security-module-hardware-security-module-hsm)
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
- [Hydra](https://github.com/ory/hydra) - Open-source OIDC & OAuth2 Server Provider.
- [Keycloak](https://github.com/keycloak/keycloak) - Open-source Identity and Access Management. Supports OIDC, OAuth 2 and SAML 2, LDAP and AD directories, password policies.
- [Casdoor](https://github.com/casbin/casdoor) - A UI-first centralized authentication / Single-Sign-On (SSO) platform based. Supports OIDC and OAuth 2, social logins, user management, 2FA based on Email and SMS.
- [authentik](https://github.com/goauthentik/authentik) - Open-source Identity Provider similar to Keycloak.
- [ZITADEL](https://github.com/zitadel/zitadel) - An Open-Source solution built with Go and Angular to manage all your systems, users and service accounts together with their roles and external identities. ZITADEL provides you with OIDC, OAuth 2.0, login & register flows, passwordless and MFA authentication. All this is built on top of eventsourcing in combination with CQRS to provide a great audit trail.
- [a12n-server](https://github.com/curveball/a12n-server) - A simple authentication system which only implements the relevant parts of the OAuth2 standards.
- [Logto](https://github.com/logto-io/logto) - An IAM infrastructure for modern apps and SaaS products, supporting OIDC, OAuth 2.0 and SAML for authentication and authorization.
- [Authgear](https://github.com/authgear/authgear-server) - Open-source authentication-as-a-service solution. It includes the code for the server, AuthUI, the Portal, and Admin API.
- [Scalekit](https://scalekit.com/) - Developer platform for enterprise authentication, providing full-stack auth, SSO, SCIM provisioning, API authentication, and MCP/agent auth for B2B applications.
