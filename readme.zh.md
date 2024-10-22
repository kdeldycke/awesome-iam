<!--lint disable awesome-heading-->

<p align="center">
  <a href="https://github.com/kdeldycke/awesome-iam#readme">
    <img src="https://raw.githubusercontent.com/kdeldycke/awesome-iam/main/assets/awesome-iam-header.jpg" alt="Awesome IAM">
  </a>
</p>

<p align="center">
  <a href="https://github.com/kdeldycke/awesome-iam#readme" hreflang="en"><img src="https://img.shields.io/badge/lang-English-blue?style=flat-square" lang="en" alt="English"></a>
  <a href="https://github.com/kdeldycke/awesome-iam/blob/main/readme.zh.md" hreflang="zh"><img src="https://img.shields.io/badge/lang-汉语-blue?style=flat-square" lang="zh" alt="汉语"></a>
</p>

<p align="center">
  <sup><a href="#sponsor-def">此列表由以下机构赞助<sup id="sponsor-ref">[0]</sup></a>：</sup><br>
</p>

<p align="center">
  <a href="https://www.descope.com/?utm_source=awesome-iam&utm_medium=referral&utm_campaign=awesome-iam-oss-sponsorship">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/kdeldycke/awesome-iam/main/assets/descope-logo-dark-background.svg">
      <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/kdeldycke/awesome-iam/main/assets/descope-logo-light-background.svg">
      <img width="300" src="https://raw.githubusercontent.com/kdeldycke/awesome-iam/main/assets/descope-logo-light-background.svg">
    </picture>
    <br/>
    <strong>拖放您的身份验证。</strong><br/>
    使用几行代码向您的应用程序添加身份验证、用户管理和授权。
  </a>
</p>

<p align="center">
  <a href="https://www.cerbos.dev/?utm_campaign=brand_cerbos&utm_source=awesome_iam&utm_medium=github&utm_content=&utm_term=">
    <img width="600" src="https://raw.githubusercontent.com/kdeldycke/awesome-iam/main/assets/cerbos-banner.svg">
    <br/>
    为您的应用构建可扩展的，细粒度的授权。 <strong>尝试Cerbos </strong>，是用于授权，测试和部署访问策略的授权管理系统。
  </a>
</p>

---

<p align="center">
  <i>Trusting is hard. Knowing who to trust, even harder.(信任是困难的。知道该信任谁，更难。)</i><br>
  — Maria V. Snyder<sup id="intro-quote-ref"><a href="#intro-quote-def">[1]</a></sup>
</p>

<!--lint disable double-link-->

[IAM](https://zh.wikipedia.org/wiki/身份管理) 代表身份和访问管理。 它是一个复杂的域，涵盖**用户帐户、身份验证、授权、角色、权限和隐私**。 它是云服务平台的重要支柱，是用户、产品和安全的交汇点。[另一个支柱是账单和支付 💰](https://github.com/kdeldycke/awesome-billing/).

这个精选清单 [![Awesome](https://awesome.re/badge-flat.svg)](https://github.com/sindresorhus/awesome) 以全面且可操作的方式公开该领域的所有技术、协议和行话。

<!--lint enable double-link-->

## Contents

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [概述](#概述)
- [安全](#安全)
- [账户管理](#账户管理)
- [密码学](#密码学)
  - [标识符](#标识符)
- [零信任网络](#零信任网络)
- [认证](#认证)
  - [基于密码](#基于密码)
- [多因素](#多因素)
  - [基于短信](#基于短信)
- [无密码](#无密码)
  - [WebAuthn](#webauthn)
  - [安全密钥](#安全密钥)
  - [公钥基础设施](#公钥基础设施)
  - [JWT](#jwt)
- [授权](#授权)
  - [策略模型](#策略模型)
  - [开源策略框架](#开源策略框架)
  - [AWS 策略工具](#AWS-策略工具)
  - [Macaroons](#macaroons)
- [OAuth2 & OpenID](#oauth2--openid)
- [SAML](#saml)
- [秘密管理](#秘密管理)
  - [硬件安全模块 (HSM)](#硬件安全模块-hsm)
- [信任与安全](#信任与安全)
  - [用户身份](#用户身份)
  - [欺诈](#欺诈)
  - [Moderation](#moderation)
  - [威胁情报](#威胁情报)
  - [验证码](#验证码)
- [黑名单](#黑名单)
  - [主机名和子域](#主机名和子域)
  - [邮件](#邮件)
  - [保留的 ID](#保留的-ID)
  - [诽谤](#诽谤)
- [隐私](#隐私)
  - [匿名化](#匿名化)
  - [GDPR](#gdpr)
- [UX/UI](#uxui)
- [竞争分析](#竞争分析)
- [历史](#历史)

<!-- mdformat-toc end -->

## 概述

<img align="right" width="50%" src="./assets/cloud-software-stack-iam.jpg"/>

在[云计算概述](http://web.stanford.edu/class/cs349d/docs/L01_overview.pdf)的斯坦福课程中，提供的平台的软件架构如右图所示 →

在这里，我们列出了全局：域的定义和战略重要性、它在更大的生态系统中的位置，以及一些关键特性。

- [EnterpriseReady SaaS 功能指南](https://www.enterpriseready.io) - 大多数让 B2B 用户满意的功能将由 IAM 外围实现。

- [IAM 很难，真的很难](https://twitter.com/kmcquade3/status/1291801858676228098) - “过于宽松的 AWS IAM 策略允许 `s3:GetObject` 访问 `*`（所有）资源”，导致 Capital One 被罚款 8000 万美元。这是作为企业主不能忽视 IAM 的唯一原因。

- [IAM 是真正的云锁定](https://forrestbrazeal.com/2019/02/18/cloud-irregular-iam-is-the-real-cloud-lock-in/) - 虽然是小小的 *点击诱饵*，但作者承认“这取决于您对他们的信任程度 1. 继续经营； 2. 不抬高价格； 3. 不贬低您下属的服务； 4. 在业务加速方面为您提供的价值多于他们在灵活性方面带来的价值。

## 安全

安全性是 IAM 基金会最核心的支柱之一。 这里有一些广泛的概念。

- [企业信息安全](https://infosec.mozilla.org) - Mozilla 的安全和访问指南。

- [缓解云漏洞](https://media.defense.gov/2020/Jan/22/2002237484/-1/-1/0/CSI-MITIGATING-CLOUD-VULNERABILITIES_20200121.PDF) - “本文档将云漏洞分为四类（配置错误、访问控制不当、共享租户漏洞和供应链漏洞）”。

- [Cartography](https://github.com/lyft/cartography) - 一种基于 Neo4J 的工具，用于映射服务和资源之间的依赖关系和关系。 支持 AWS、GCP、GSuite、Okta 和 GitHub。

- [AWS 安全性和 IAM 开放指南](https://github.com/open-guides/og-aws#security-and-iam)

## 账户管理

IAM 的基础：用户、组、角色和权限的定义和生命周期。

- [作为一个用户，我想要…](https://mobile.twitter.com/oktopushup/status/1030457418206068736) - 客户管理的元评论家，其中业务预期的功能与真实用户需求发生冲突，以虚构项目经理编写的用户故事的形式出现。

- [终端用户关心但程序员不关心的事情](https://instadeq.com/blog/posts/things-end-users-care-about-but-programmers-dont/) - 与上述精神相同，但范围更广：所有我们作为开发者而忽视但用户真正关心的小事。在这个列表的顶部是以账户为中心的功能，多样化的集成和导入/导出工具。也就是所有企业客户需要涵盖的内容。

- [将账户、用户和登录/授权细节分开](https://news.ycombinator.com/item?id=21151830) - 为面向未来的 IAM API 奠定基础的合理建议。

- [超越用户名的身份](https://lord.io/blog/2020/usernames/) - 关于用户名作为标识符的概念，以及当 unicode 字符满足唯一性要求时引入的复杂问题。

- [Kratos](https://github.com/ory/kratos) -用户登录、用户注册、2FA 和个人资料管理。

- [Conjur](https://github.com/cyberark/conjur) - 自动保护特权用户和机器身份所使用的秘密信息。

- [SuperTokens](https://github.com/supertokens/supertokens-core) - 用于登录和会话管理的开源项目，支持无密码、社交登录、电子邮件和电话登录。

- [UserFrosting](https://github.com/userfrosting/UserFrosting) - 现代PHP用户登录和管理框架。

## 密码学

整个认证技术栈是基于密码学原理的。这一点不能被忽视。

- [密码学的正确答案](https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html) - 为非密码学工程师的开发人员提供的一组最新建议。甚至还有[更短的摘要](https://news.ycombinator.com/item?id=16749140)可用。

- [真实世界的密码研讨会](https://rwc.iacr.org) - 旨在将密码学研究人员与开发人员聚集在一起，专注于在互联网、云和嵌入式设备等现实环境中的使用。

- [密码学概述](https://www.garykessler.net/library/crypto.html) - “这篇论文有两个主要目的。 首先是定义基本密码方法背后的一些术语和概念，并提供一种方法来比较当今使用的无数密码方案。 第二个是提供一些当今使用的密码学的真实例子。”

- [我们喜欢的论文：密码学](https://github.com/papers-we-love/papers-we-love/blob/master/cryptography/README.md) - 密码学基础论文。

- [加密哈希函数的生命周期](http://valerieaurora.org/hash.html) - "如果你使用逐个哈希值比较来生成可由恶意用户提供的数据的地址，你应该有一个计划，每隔几年就迁移到一个新的哈希值"。

### 标识符

令牌、主键、UUID......无论最终用途是什么，你都必须生成这些具有一定随机性和唯一性的数字。

- [对任何依赖随机生成的号码的设备的安全建议](https://www.av8n.com/computer/htm/secure-random.htm) - "'随机数生成器'这一短语应作如下解析。它是一个数字的随机发生器。它不是一个随机数的生成器"。

- [RFC #4122: UUID - 安全方面的考虑](https://www.rfc-editor.org/rfc/rfc4122#section-6) - "不要认为UUID难以猜测；它们不应该被用作安全能力（仅仅拥有它就能授予访问权的标识）"。UUIDs被设计成唯一的，而不是随机的或不可预测的：不要把UUIDs作为一个秘密。

- [Awesome Identifiers](https://adileo.github.io/awesome-identifiers/) - 所有标识符格式的一个基准。

- [Awesome GUID](https://github.com/secretGeek/AwesomeGUID) - 对唯一标识的全局性方面做的有趣讨论。

## 零信任网络

零信任网络安全的运作原则是 "永不信任，永远验证"。

- [BeyondCorp：企业安全的新方法](https://www.usenix.org/system/files/login/articles/login_dec14_02_ward.pdf) - 简要概述谷歌的零信任网络方案。

- [什么是 BeyondCorp？ 什么是身份感知代理？](https://medium.com/google-cloud/what-is-beyondcorp-what-is-identity-aware-proxy-de525d9b3f90) - 越来越多的公司添加了额外的 VPN、防火墙、限制和限制层，导致糟糕的体验和轻微的安全增益。是存在更好的方法。

- [oathkeeper](https://github.com/ory/oathkeeper) - 身份与访问代理和访问控制决策API，对进入的HTTP请求进行认证、授权和变异。受BeyondCorp / Zero Trust白皮书的启发。

- [transcend](https://github.com/cogolabs/transcend) - BeyondCorp 启发的访问代理服务器。

- [Pomerium](https://github.com/pomerium/pomerium) - 一种身份感知代理，支持对内部应用程序的安全访问。

## 认证

用于确认你是相应的人的协议和技术。

- [API Tokens: A Tedious Survey](https://fly.io/blog/api-tokens-a-tedious-survey/) - 对终端用户 API 的所有基于令牌的认证方案进行概述和比较。

- [服务间认证方案的儿童花园](https://web.archive.org/web/20200507173734/https://latacora.micro.blog/a-childs-garden/) - 与上述精神相同，但这次是在服务层面。

- [在 Facebook 扩展后端身份验证](https://www.youtube.com/watch?v=kY-Bkv3qxMc) - 简而言之，如何做：1.小的信任根；2.TLS 是不够的；3.基于证书的令牌；4.加密认证令牌（CATs）。更多细节见[幻灯片](https://rwc.iacr.org/2018/Slides/Lewi.pdf)。

### 基于密码

- [新的 NIST 密码指南](https://pciguru.wordpress.com/2019/03/11/the-new-nist-password-guidance/) - [NIST Special Publication 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) 的摘要，涵盖了新的密码复杂性指南。

- [密码存储备忘](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) - 减缓离线攻击的唯一方法是谨慎地选择尽可能密集资源的哈希算法。

- [密码过期作废](https://techcrunch.com/2019/06/02/password-expiration-is-dead-long-live-your-passwords/) - 最近的科学研究对许多长期存在的密码安全实践（例如密码过期策略）的价值提出质疑，并指出更好的替代方案，例如执行禁止密码列表和 MFA。

- [更强大、更实用的密码的实用建议](http://www.andrew.cmu.edu/user/nicolasc/publications/Tan-CCS20.pdf) - 本研究建议关联如下几个方法：针对常见泄露密码的黑名单检查、无字符类要求的密码策略、最小强度策略。

- [银行、任意的密码限制以及为什么它们并不重要](https://www.troyhunt.com/banks-arbitrary-password-restrictions-and-why-they-dont-matter/) - “对长度和字符组成的任意低限制是不好的。 它们看起来很糟糕，会导致对安全状况的负面猜测，并且会破坏密码管理器等工具。”

- [愚蠢的密码规则](https://github.com/dumb-password-rules/dumb-password-rules) - 使用愚蠢的密码规则的糟糕网站。

- [普通文本罪犯](https://plaintextoffenders.com/about/) - 公开羞辱以纯文本存储密码的网站。

- [密码管理器资源](https://github.com/apple/password-manager-resources) - 一个按网站分类的密码规则、更改URL和怪癖的集合。

- [更改密码的著名网址](https://github.com/WICG/change-password-url) - 定义密码更新的网站资源的规范。

- [如何改变已经散列的用户密码的散列方案](https://news.ycombinator.com/item?id=20109360) - 好消息是：你并没有被困在一个传统的密码保存方案中。这里有一个技巧，可以透明地升级到更强大的散列算法。

## 多因素

在仅密码的AUTH的基础上，这些方案中要求用户提供两个或更多的证据（或因素）。

- [打破密码的依赖性。微软最后一公里的挑战](https://www.youtube.com/watch?v=B_mhJO2qHlQ) - 帐户黑客攻击的主要来源是密码喷洒（在 SMTP、IMAP、POP 等传统身份验证上），其次是重放攻击。 要点：密码不安全，使用并执行 MFA。

- [超越密码：2FA、U2F 和 Google 高级保护](https://www.troyhunt.com/beyond-passwords-2fa-u2f-and-google-advanced-protection/) - 全面了解所有这些技术。

- [回溯认证的长期比较研究](https://maximiliangolla.com/files/2019/papers/usec2019-30-wip-fallback-long-term-study-finalv5.pdf) - 要点：“基于电子邮件和短信的方案更有用。 另一方面，基于指定受托人和个人知识问题的机制在便利性和效率方面都存在不足。”

- [秘密、谎言和帐户恢复：谷歌使用个人知识问题的经验教训](https://static.googleusercontent.com/media/research.google.com/en/us/pubs/archive/43783.pdf) - "我们的分析证实，秘密问题通常提供的安全级别远远低于用户选择的密码。(......)令人惊讶的是，我们发现造成这种不安全的一个重要原因是用户经常不如实回答。(......)在可用性方面，我们表明秘密答案的记忆性出奇的差"。

- [基本的账户卫生在防止劫持方面的效果如何](https://security.googleblog.com/2019/05/new-research-how-effective-is-basic.html) - 谷歌安全团队的数据显示，2FA 阻止了100%的自动机器人黑客。

- [你的 Pa\$\$word 无关紧要](https://techcommunity.microsoft.com/t5/Azure-Active-Directory-Identity/Your-Pa-word-doesn-t-matter/ba-p/731984) - 与上述 Microsoft 的结论相同：“根据我们的研究，如果您使用 MFA，您的帐户被盗用的可能性会降低 99.9% 以上。”

- [攻击 Google 身份验证器](https://unix-ninja.com/p/attacking_google_authenticator) - 可能处于偏执狂的边缘，但可能是限制 2FA 验证尝试的原因。

- [通过破解语音邮件系统来破坏在线帐户](https://www.martinvigo.com/voicemailcracker/) - 或者说，为什么你不应该依靠自动电话作为联系用户和重置密码、2FA 或进行任何形式的验证的方法。与基于短信的 2FA 不一样，它目前是不安全的，可以通过其最薄弱的环节：语音邮件系统的方式进行破坏。

- [2019 年正确对待 2FA](https://blog.trailofbits.com/2019/06/20/getting-2fa-right-in-2019/) - 关于 2FA 的用户体验方面。

- [2FA 缺少一个关键功能](https://syslog.ravelin.com/2fa-is-missing-a-key-feature-c781c3861db) - “当我的 2FA 代码输入错误时，我想知道这件事”。

- [南极洲的 SMS 多因素认证](https://brr.fyi/posts/sms-mfa) - 不起作用，因为在南极洲的站点没有手机信号塔。

- [Authelia](https://github.com/authelia/authelia) - 开源认证和授权服务器，通过网络门户为你的应用程序提供双因素认证和单点登录（SSO）。

- [Kanidm](https://github.com/kanidm/kanidm) - 简单、安全、快速的身份管理平台。

### 基于短信

太长了，细节详情见下面的文章

- [短信 2FA 认证已被 NIST 废止](https://techcrunch.com/2016/07/25/nist-declares-the-age-of-sms-based-2-factor-authentication-over/) - NIST 表示，自2016年以来，通过短信进行的 2FA 是糟糕的、可怕的。

- [SMS：最流行但最不安全的 2FA 方法](https://www.allthingsauth.com/2018/02/27/sms-the-most-popular-and-least-secure-2fa-method/)

- [SMS 2FA 安全吗？ 不。](https://www.issms2fasecure.com) - 权威研究项目展示了 SIM 交换的成功尝试。

- [黑客攻击 Twitter CEO 杰克·多尔西 (Jack Dorsey) 在“SIM 交换”中。 你也有危险。](https://www.nytimes.com/2019/09/05/technology/sim-swap-jack-dorsey-hack.html)

- [美国电话电报公司代表将其手机账户的控制权交给黑客](https://www.theregister.co.uk/2017/07/10/att_falls_for_hacker_tricks/)

- [我一生中最昂贵的一课：SIM 端口黑客攻击的详细信息](https://medium.com/coinmonks/the-most-expensive-lesson-of-my-life-details-of-sim-port-hack-35de11517124)

- [SIM 卡交换恐怖故事](https://www.zdnet.com/article/sim-swap-horror-story-ive-lost-decades-of-data-and-google-wont-lift-a-finger/)

- [AWS 正在逐步弃用基于 SMS 的 2FA](https://aws.amazon.com/iam/details/mfa/) - “我们鼓励您通过 U2F 安全密钥、硬件设备或虚拟（基于软件的）MFA 设备使用 MFA。 您可以在 2019 年 1 月 31 日之前继续使用此功能。”

## 无密码

- [无密码的争论](https://web.archive.org/web/20190515230752/https://biarity.gitlab.io/2018/02/23/passwordless/) - 密码不是用户身份验证的全部和最终结果。这篇文章试图告诉你为什么。

- [神奇的链接 - 它们实际上已经过时了吗？](https://zitadel.com/blog/magic-links) - 什么是神奇的链接，它们的起源，优点和缺点。

### WebAuthn

[fido2项目](https://en.wikipedia.org/wiki/fido_alliance#fido2) 的一部分，也以 *passkeys* 的用户友好名称为名。

- [WebAuthn 指南](https://webauthn.guide) - 这是一份非常容易理解的WebAuthn指南，该标准允许 "服务器使用公钥加密技术而不是密码来注册和验证用户"，所有主要浏览器都支持。

- [清除对Passkeys的一些误解](https://www.stavros.io/posts/clearing-up-some-passkeys-misconceptions/) - 或者为什么Passkey不比密码差。

### 安全密钥

- [Webauthn 和安全密钥](https://www.imperialviolet.org/2018/03/27/webauthn.html) - 描述身份验证如何使用安全密钥，详细说明协议，以及它们如何与 WebAuthn 结合。 要点：“但是，无法使用 webauthn 创建 U2F 密钥。 (...) 所以先完成登录过程到 webauthn 的过渡，然后再过渡注册。”

- [开始使用安全密钥](https://paulstamatiou.com/getting-started-with-security-keys/) - 使用 FIDO2、WebAuthn 和安全密钥保持在线安全和防止网络钓鱼的实用指南。

- [Solo](https://github.com/solokeys/solo) - 通过 USB + NFC 打开支持 FIDO2 和 U2F 的安全密钥。

- [OpenSK](https://github.com/google/OpenSK) - 用 Rust 编写的安全密钥的开源实现，支持 FIDO U2F 和 FIDO2 标准。

- [YubiKey 指南](https://github.com/drduh/YubiKey-Guide) - 使用 YubiKey 作为存储 GPG 加密、签名和身份验证密钥的智能卡的指南，它也可以用于 SSH。 本文档中的许多原则适用于其他智能卡设备。

- [YubiKey at Datadog](https://github.com/DataDog/yubikey) - Yubikey、U2F、GPG、git、SSH、Keybase、VMware Fusion 和 Docker Content Trust 设置指南。

### 公钥基础设施

基于证书的身份验证。

- [忙碌者的 PKI](https://gist.github.com/hoffa/5a939fd0f3bcd2a6a0e4754cb2cf3f1b) - 重要内容的快速概述。

- [关于证书和 PKI 你应该知道但不敢问的一切](https://smallstep.com/blog/everything-pki.html) - PKI 让你以加密方式定义一个系统。它是通用的，并且是供应商中立的。

- [`lemur`](https://github.com/Netflix/lemur) - 充当 CA 和环境之间的代理，为开发人员提供中央门户以颁发具有“正常”默认值的 TLS 证书。

- [CFSSL](https://github.com/cloudflare/cfssl) - CloudFlare 的 PKI/TLS 瑞士军刀。 用于签署、验证和捆绑 TLS 证书的命令行工具和 HTTP API 服务器。

- [JA3](https://github.com/salesforce/ja3) - 创建 SSL/TLS 客户端指纹的方法，应该可以在任何平台上轻松生成，并且可以轻松共享以获取威胁情报。

### JWT

[JSON 网络令牌](https://en.wikipedia.org/wiki/JSON_Web_Token) 是不记名的令牌。

- [JSON Web Token 简介](https://jwt.io/introduction/) - 通过本文快速了解 JWT。

- [了解如何使用 JWT 进行身份验证](https://github.com/dwyl/learn-json-web-tokens) - 了解如何使用 JWT 来保护您的 Web 应用程序。

- [使用 JSON Web 令牌作为 API 密钥](https://auth0.com/blog/using-json-web-tokens-as-api-keys/) - 与 API 密钥相比，JWT 提供了细粒度的安全性、同质身份验证架构、去中心化发布、OAuth2 合规性、可调试性、过期控制、设备管理。

- [管理一个安全的 JSON 网络令牌实现](https://cursorblog.com/managing-a-secure-json-web-token-implementation/) - JWT有各种各样的灵活性，使它很难用好。

- [硬编码的密钥、未经验证的令牌和其他常见的 JWT 错误](https://r2c.dev/blog/2020/hardcoded-secrets-unverified-tokens-and-other-common-jwt-mistakes/) - 对所有 JWT 的陷阱进行了很好的总结。

- [将 JSON 网络令牌 API 密钥添加到拒绝列表中](https://auth0.com/blog/denylist-json-web-token-api-keys/) - 在令牌失效时。

- [停止对会话使用 JWT](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/) - 以及[为什么你的 "解决方案 "不起作用](http://cryto.net/%7Ejoepie91/blog/2016/06/19/stop-using-jwt-for-sessions-part-2-why-your-solution-doesnt-work/)，因为[无状态的JWT令牌不能被废止或更新](https://news.ycombinator.com/item?id=18354141)。它们会引入大小问题或安全问题，这取决于你将它们存储在哪里。有状态的 JWT 令牌在功能上与会话 cookie 相同，但没有经过实战检验和充分审查的实现或客户端支持。

- [JWT、JWS 和 JWE 是为不那么愚蠢的人准备的!](https://medium.facilelogin.com/jwt-jws-and-jwe-for-not-so-dummies-b63310d201a3) - 经过签名的 JWT 被称为 JWS（JSON Web Signature）。事实上，JWT 本身并不存在--它必须是一个JWS 或 JWE（JSON Web Encryption）。它就像一个抽象类，JWS 和 JWE 是具体的实现。

- [JOSE 是每个人都应该避免的坏标准](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid) - 这些标准要么是完全破碎的，要么是难以驾驭的复杂雷区。

- [JWT.io](https://jwt.io) - 允许你解码、验证和生成JWT。

- [`loginsrv`](https://github.com/tarent/loginsrv) - 独立的简约登录服务器，为多个登录后端（htpasswd、OSIAM、用户/密码、HTTP 基本身份验证、OAuth2：GitHub、Google、Bitbucket、Facebook、GitLab）提供 JWT 登录。

- [jwtXploiter](https://github.com/DontPanicO/jwtXploiter) - 一个测试 json web token 安全性的工具。

## 授权

现在我们知道你就是你。 但是你可以做你想做的事吗？

策略规范是科学，执行是艺术。

### 策略模型

作为一个概念，访问控制策略可以设计为遵循非常不同的原型，从经典的[访问控制列表](https://en.wikipedia.org/wiki/Access-control_list)到[基于角色的访问控制](https://zh.wikipedia.org/wiki/以角色為基礎的存取控制)。 在本节中，我们将探索许多不同的模式和架构。

- [为什么授权很难](https://www.osohq.com/post/why-authorization-is-hard) - 因为它需要在很多地方需要的执行、决策架构上进行多重权衡以将业务逻辑与授权逻辑分开，以及在建模上平衡功率和复杂性。

- [用户授权的永无止境的产品要求](https://alexolivier.me/posts/the-never-ending-product-requirements-of-user-authorization) - 基于角色的简单授权模型是如何不够的，并且由于产品包装、数据定位、企业组织和合规性而迅速变得复杂。

- [拟采用的 RBAC 方式](https://tailscale.com/blog/rbac-like-it-was-meant-to-be/) -我们如何从 DAC（unix 权限、秘密 URL）到 MAC（DRM、MFA、2FA、SELinux），再到 RBAC。 详细说明后者如何允许更好地建模策略、ACL、用户和组。

- [细粒度权限的案例](https://cerbos.dev/blog/the-case-for-granular-permissions) - 讨论 RBAC 的局限性以及 ABAC（基于属性的访问控制）如何解决这些问题。

- [寻找完美的访问控制系统](https://goteleport.com/blog/access-controls/) - 授权计划的历史渊源。暗示了不同团队和组织之间共享、信任和授权的未来。

- [GCP IAM语法比AWS更好](https://ucarion.com/iam-operation-syntax) - GCP中许可设计的细节可改善发育器的经验。

- [使用 SMT 的 AWS 访问策略的基于语义的自动推理](https://d1.awsstatic.com/Security/pdfs/Semantic_Based_Automated_Reasoning_for_AWS_Access_Policies_Using_SMT.pdf) - Zelkova 是 AWS 的做法。 该系统对IAM策略进行符号分析，根据用户权限和访问约束解决资源可达性问题。 另请参阅更高级别的 [在 re:inforce 2019 上给出的介绍](https://youtu.be/x6wsTFnU3eY?t=2111)。

- [授权学院](https://www.osohq.com/academy) - 对授权进行深入的、与供应商无关的处理，强调心智模型。本指南向读者展示了如何考虑他们的授权需求，以便就其授权架构和模型做出正确的决策。

- [服务到服务授权：非用户校长指南](https://www.cerbos.dev/blog/service-to-service-authorization) - 发现将身份分配给服务（非用户校长）如何简化身份验证，增强安全性和简化复杂分布式系统中的授权。 IAM团队管理微服务和API的有用指南。

### RBAC 框架

[以角色為基礎的存取控制l](https://zh.wikipedia.org/wiki/以角色為基礎的存取控制l) 是通过角色绘制用户将用户映射到权限的经典模型。

- [Athenz](https://github.com/yahoo/athenz) - 支持服务身份验证以及基于角色的配置授权的服务和库集。

- [Biscuit](https://www.clever-cloud.com/blog/engineering/2021/04/12/introduction-to-biscuit/) - Biscuit 合并了来自 cookies、JWTs、macaroons 和 Open Policy Agent 的概念。 “它提供了一种基于 Datalog 的逻辑语言来编写授权策略。 它可以存储数据，如 JWT，或像 Macaroons 这样的小条件，但它也能够表示更复杂的规则，如基于角色的访问控制、委托、层次结构。”

- [Oso](https://github.com/osohq/oso) - 一个包含电池的库，用于在您的应用程序中构建授权。

- [Cerbos](https://github.com/cerbos/cerbos) - 用于编写上下文感知访问控制策略的授权端点。

### ABAC 框架

[Attribute-Based Access Control](https://en.wikipedia.org/wiki/Attribute-based_access_control) 是RBAC的演变，其中角色被属性取代，从而实现了更复杂的基于策略的访问控制。

- [Keto](https://github.com/ory/keto) - 策略决定点。 它使用一组访问控制策略，类似于 AWS 策略，以确定主体是否有权对资源执行特定操作。

- [Ladon](https://github.com/ory/ladon) - 受 AWS 启发的访问控制库。

- [Casbin](https://github.com/casbin/casbin) - Golang 项目的开源访问控制库。

- [Open Policy Agent](https://github.com/open-policy-agent/opa) - 一个开源通用决策引擎，用于创建和实施基于属性的访问控制 (ABAC) 策略。

### ReBAC 框架

[基于关系的访问控制（ReBAC）](https://zh.wikipedia.org/wiki/基于关系的访问控制) 模型是RBAC的更灵活，功能更强大的版本，并且是云系统的首选。

- [Zanzibar：谷歌一致的全球授权系统](https://ai.google/research/pubs/pub48190) - 可扩展到每秒数万亿个访问控制列表和数百万个授权请求，以支持数十亿人使用的服务。 在 3 年的生产使用中，它一直保持低于 10 毫秒的 95% 延迟和高于 99.999% 的可用性。 [论文中没有的其他内容](https://twitter.com/LeaKissner/status/1136626971566149633)。 [Zanzibar Academy](https://zanzibar.academy/) 是一个致力于解释 Zanzibar 运作方式的网站。

- [SpiceDB](https://github.com/authzed/spicedb) - 一个开源数据库系统，用于管理受 Zanzibar 启发的安全关键应用程序权限。

- [Permify](https://github.com/Permify/permify) - 另一项开源授权为受Google Zanzibar启发的服务，并查看 [与其他Zanzibar启发的工具相比](https://permify.notion.site/Differentiation-Between-Zanzibar-Products-ad4732da62e64655bc82d3abe25f48b6)。

- [Topaz](https://github.com/aserto-dev/topaz) - 一个开源项目，它将 OPA 的策略即代码和决策日志记录与 Zanzibar 模型目录相结合。

- [Open Policy Administration Layer](https://github.com/permitio/opal) - OPA 的开源管理层，实时检测政策和政策数据的变化，并将实时更新推送给 OPA 代理。 OPAL 使开放策略达到实时应用程序所需的速度。

- [Warrant](https://github.com/warrant-dev/warrant) - 基于关系的访问控制（REBAC）引擎（受Google Zanzibar的启发）也能够执行任何授权范式，包括RBAC和ABAC。

### AWS 策略工具

专门针对 [AWS IAM 策略](http://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html) 生态系统的工具和资源。

- [AWS IAM 安全工具参考](https://ramimac.me/aws-iam-tools-2024) - AWS IAM的（维护）工具的全面列表。

- [成为 AWS IAM 策略忍者](https://www.youtube.com/watch?v=y7-fAT3z8Lo) - “在亚马逊工作近 5 年的时间里，我每天、每周都会抽出一点时间浏览论坛、客户工单，试图找出人们遇到问题的地方。”

- [AWS IAM 角色，一个不必要的复杂故事](https://infosec.rodeo/posts/thoughts-on-aws-iam/) - 快速增长的 AWS 的历史解释了当前方案是如何形成的，以及它与 GCP 资源层次结构的比较。

- [Policy Sentry](https://github.com/salesforce/policy_sentry) - 手动编写具有安全意识的 IAM 策略可能非常乏味且效率低下。 Policy Sentry 可帮助用户在几秒钟内创建最低权限策略。

- [PolicyUniverse](https://github.com/Netflix-Skunkworks/policyuniverse) - 解析和处理 AWS 策略、语句、ARN 和通配符。

- [IAM Floyd](https://github.com/udondan/iam-floyd) - 具有流畅界面的 AWS IAM 策略语句生成器。 通过 IntelliSense 提供条件和 ARN 生成，帮助创建类型安全的 IAM 策略并编写更具限制性/安全的语句。 适用于 Node.js、Python、.Net 和 Java。

- [ConsoleMe](https://github.com/Netflix/consoleme) - 一种适用于 AWS 的自助服务工具，它根据跨多个账户管理权限的授权级别为最终用户和管理员提供登录账户的凭据和控制台访问权限，同时鼓励使用最低权限。

- [IAMbic](https://github.com/noqdev/iambic) - 適用於 IAM 的 GitOps。 Cloud IAM 的 Terraform。 IAMbic 是一個多雲身份和訪問管理 (IAM) 控制平面，可集中和簡化雲訪問和權限。 它在版本控制中維護 IAM 的最終一致、人類可讀的雙向表示。

### Macaroons

分配和委托授权的巧妙好奇。

- [五分钟或更短时间内完成 Google 的 Macaroon](https://web.archive.org/web/20240521142227/https://blog.bren2010.io/blog/googles-macaroons) - 如果给我一个授权我在某些限制下执行某些操作的 Macaroon，我可以非交互地构建第二个具有更严格限制的 Macaroon，然后我可以给你。

- [Macaroons: 为云中的分散式授权提供带有上下文警告的Cookies](https://ai.google/research/pubs/pub41892) - 谷歌的原始论文。

- [Google 论文的作者比较了 Macaroons 和 JWT](https://news.ycombinator.com/item?id=14294463) - 作为 Macaroons 的消费者/验证者，它们允许您（通过第三方警告）将某些授权决定推迟给其他人，JWT 没有。

### 其他工具

- [Gubernator](https://github.com/gubernator-io/gubernator) - 高性能限速微服务和库。

## OAuth2 & OpenID

[OAuth 2.0](https://zh.wikipedia.org/wiki/开放授权#OAuth_2.0) 是一个*委托授权*框架。 [OpenID Connect (OIDC)](https://en.wikipedia.org/wiki/OpenID_Connect) 是其之上的*身份验证*层。

旧的 *OpenID* 已死； 新的 *OpenID Connect* 还没有死。

- [OAuth 身份验证的问题](http://www.thread-safe.com/2012/01/problem-with-oauth-for-authentication.html) - “问题是 OAuth 2.0 是委托授权 协议，而不是身份验证协议。” 10年后，这篇文章仍然是关于[为什么使用OpenID Connect而不是普通OAuth2](https://security.stackexchange.com/a/260519)的最好解释？

- [OAuth 和 OpenID Connect 图解指南](https://developer.okta.com/blog/2019/10/21/illustrated-guide-to-oauth-and-oidc) - 使用简化的插图解释这些标准的工作原理。

- [OAuth 2 简化版](https://aaronparecki.com/oauth-2-simplified/) - 以简化格式描述协议的参考文章，以帮助开发人员和服务提供商实施它。

- [OAuth 2.0 和 OpenID 连接（通俗易懂）](https://www.youtube.com/watch?v=996OiexHze0) - 首先介绍了这些标准是如何形成的历史背景，澄清了词汇中的不正确之处，然后详细介绍了协议及其陷阱，使其不那么令人生畏。

- [关于 OAuth (2.0) 你需要知道的一切](https://gravitational.com/blog/everything-you-need-to-know-about-oauth/) - 很好的概述和实际案例研究，介绍了开源远程访问工具 Teleport 如何允许用户通过 GitHub SSO 登录。

- [一张图看懂 OAuth](https://mobile.twitter.com/kamranahmedse/status/1276994010423361540) - 一张漂亮的总结卡。

- [如何通过六个步骤实现安全的中央认证服务](https://shopify.engineering/implement-secure-central-authentication-service-six-steps) - 有多个遗留系统要与它们自己的登录方式和账户合并？这里是如何通过 OIDC 的方式来合并所有这些混乱的系统。

- [开源 BuzzFeed 的 SSO 体验](https://increment.com/security/open-sourcing-buzzfeeds-single-sign-on-process/) - 中央认证服务 (CAS) 协议的 OAuth2 友好改编。 您会在那里找到很好的 OAuth 用户流程图。

- [OAuth 2.0 安全的当前最佳实践](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-16) - "更新和扩展了 OAuth 2.0 的安全威胁模型，以纳入自 OAuth 2.0 发布以来收集的实际经验，并涵盖了由于更广泛的应用而产生的相关新威胁"。

- [隐藏的 OAuth 攻击载体](https://portswigger.net/web-security/oauth) - 如何识别和利用 OAuth 2.0 认证机制中发现的一些关键漏洞。

- [PKCE 的解释](https://www.loginradius.com/blog/engineering/pkce/) - "PKCE 用于为 OAuth 和 OpenID Connect 中的授权代码流提供多一个安全层。"

- [Hydra](https://gethydra.sh) - 开源的 OIDC 和 OAuth2 服务器。

- [Keycloak](https://www.keycloak.org) - 开源的身份和访问管理。支持 OIDC、OAuth 2和SAML 2、LDAP 和 AD 目录、密码策略。

- [Casdoor](https://github.com/casbin/casdoor) - 基于 UI 优先的集中式身份验证/单点登录 (SSO) 平台。 支持 OIDC 和 OAuth 2、社交登录、用户管理、基于电子邮件和短信的 2FA。

- [authentik](https://goauthentik.io/?#correctness) - 类似于 Keycloak 的开源身份提供者。

- [ZITADEL](https://github.com/zitadel/zitadel) - 使用 Go 和 Angular 构建的开源解决方案，用于管理您的所有系统、用户和服务帐户及其角色和外部身份。 ZITADEL 为您提供 OIDC、OAuth 2.0、登录和注册流程、无密码和 MFA 身份验证。 所有这一切都建立在事件溯源之上，并结合 CQRS 来提供出色的审计跟踪。

- [a12n-server](https://github.com/curveball/a12n-server) - 一个简单的身份验证系统，仅实现 OAuth2 标准的相关部分。

- [Logto](https://github.com/logto-io/logto) - 使用此基于 OIDC 的身份服务构建登录、身份验证和用户身份。

- [Authgear](https://github.com/authgear/authgear-server) - 开源身份验证解决方案。它包括服务器，Authui，门户和管理API的代码。

- [OpenID 的衰落D](https://penguindreams.org/blog/the-decline-of-openid/) - OpenID 在公共网络中被替换为 OAuth 1、OAuth 2 或其他专有 SSO 协议的混合体。

- [为什么 Mastercard 不使用 OAuth 2.0](https://developer.mastercard.com/blog/why-mastercard-doesnt-use-oauth-20) - "他们这样做是为了提供消息级的完整性。OAuth 2改成了传输级的保密性/完整性。" (由 TLS 提供这个定性) ([来源](https://news.ycombinator.com/item?id=17486165)).

- [OAuth 2.0 and the Road to Hell](https://gist.github.com/nckroy/dd2d4dfc86f7d13045ad715377b6a48f) - Oauth 2.0 規範的主要作者和編輯的辭職信。

## SAML

安全断言标记语言 (SAML) 2.0 是一种在服务之间交换授权和身份验证的方法，例如上面的 OAuth/OpenID 协议。

典型的 SAML 身份提供商是机构或大公司的内部 SSO，而典型的 OIDC/OAuth 提供商是运行数据孤岛的科技公司。

- [SAML vs. OAuth](https://web.archive.org/web/20230327071347/https://www.cloudflare.com/learning/access-management/what-is-oauth/) - “OAuth 是一种授权协议：它确保 Bob 前往正确的停车场。 相比之下，SAML 是一种用于身份验证的协议，或者允许 Bob 通过警卫室。”

- [SAML 2.0 和 OAuth 2.0 的区别](https://www.ubisecure.com/uncategorized/difference-between-saml-and-oauth/) - “尽管 SAML 实际上被设计为具有广泛的适用性，但其当代用途通常转向企业 SSO 场景。 另一方面，OAuth 被设计用于 Internet 上的应用程序，尤其是委托授权。”

- [OAuth、OpenID Connect 和 SAML 之间有什么区别？](https://www.okta.com/identity-101/whats-the-difference-between-oauth-openid-connect-and-saml/) - 身份是困难的。我们总是欢迎对不同协议的另一种看法，以帮助理解这一切。

- [SAML 2.0 认证如何工作](https://gravitational.com/blog/how-saml-authentication-works/) - 概述 SSO 和 SAML 的方式和原因。

- [Web 单点登录，SAML 2.0 视角](https://blog.theodo.com/2019/06/web-single-sign-on-the-saml-2-0-perspective/) - 在公司 SSO 实施的上下文中对 SAML 工作流的另一种简要解释。

- [SAML 啤酒饮用者指南](https://duo.com/blog/the-beer-drinkers-guide-to-saml) - SAML 有时很神秘。 另一个类比可能有助于从中获得更多意义。

- [SAML 在设计上是不安全的](https://joonas.fi/2021/08/saml-is-insecure-by-design/) - 不仅奇怪，SAML 在设计上也不安全，因为它依赖于基于 XML 规范化的签名，而不是 XML 字节流。 这意味着您可以利用 XML 解析器/编码器的差异。

- [SAML 单点退出的难点 ](https://wiki.shibboleth.net/confluence/display/CONCEPT/SLOIssues) - 关于单点注销实施的技术和用户体验问题。

- [SSO的耻辱墙](https://sso.tax) - 对 SaaS 提供商为在其产品上激活 SSO 而实行的过高定价进行了有记录的咆哮。 作者的观点是，作为核心安全功能，SSO 应该合理定价，而不是排他性层的一部分。

## 秘密管理

允许存储和使用秘密的架构、软件和硬件允许进行身份验证和授权，同时维护信任链。

- [Netflix 的大规模秘密](https://www.youtube.com/watch?v=K0EOPddWpsE) - 基于盲签名的解决方案。 见[幻灯片](https://rwc.iacr.org/2018/Slides/Mehta.pdf).

- [Google 内部 KMS 中的高可用性](https://www.youtube.com/watch?v=5T_c-lqgjso) - 不是 GCP 的 KMS，而是其基础架构的核心。 见[幻灯片](https://rwc.iacr.org/2018/Slides/Kanagala.pdf).

- [HashiCorp Vault](https://www.vaultproject.io) - 保护、存储和严格控制对令牌、密码、证书、加密密钥的访问。

- [Infisical](https://github.com/Infisical/infisical) - HashiCorp Vault 的替代品。

- [`sops`](https://github.com/mozilla/sops) - 加密 YAML 和 JSON 文件的值，而不是密钥。

- [`gitleaks`](https://github.com/zricethezav/gitleaks) - 审计 git repos 的秘密。

- [`truffleHog`](https://github.com/dxa4481/truffleHog) - 在 git 存储库中搜索高熵字符串和秘密，深入挖掘提交历史。

- [Keywhiz](https://square.github.io/keywhiz/) - 一种用于管理和分发机密的系统，可以很好地适应面向服务的体系结构 (SOA)。

- [`roca`](https://github.com/crocs-muni/roca) - 用于检查各种密钥格式的弱 RSA 模块的 Python 模块。

### 硬件安全模块 (HSM)

HSM 是在硬件层面保证秘密管理安全的物理设备。

- [HSM：它们是什么以及为什么您今天可能（间接）使用过它们](https://rwc.iacr.org/2015/Slides/RWC-2015-Hampton.pdf) - HSM 用法的真正基本概述。

- [AWS Cloud HSM 硬件花絮](https://news.ycombinator.com/item?id=16759383) - AWS CloudHSM Classic 由 SafeNet 的 Luna HSM 提供支持，当前的 CloudHSM 依赖于 Cavium 的 Nitrox，它允许分区的“虚拟 HSM”。

- [CrypTech](https://cryptech.is) - 一个开放的硬件 HSM。

- [Keystone](https://keystone-enclave.org) - 用于基于 RISC-V 架构构建具有安全硬件飞地的可信执行环境 (TEE) 的开源项目。

- [Project Oak](https://github.com/project-oak/oak) - 数据安全传输、存储和处理的规范和参考实现。

- [大家冷静点，这是抢劫！](https://www.sstic.org/2019/presentation/hsm/) - HSM 漏洞和可利用性的案例研究（这一篇文章是法语 😅）。

## 信任与安全

一旦你有了一个重要的用户群，它就被称为一个社区。然后你将负责保护它：客户、人们、公司、企业，并促进其中发生的所有互动和交易。

信任与安全部门是一个受政策驱动和当地法律约束的关键中介机构，可能由一个由 24/7 运营商和高度先进的调节和管理工具系统组成的跨职能团队体现。 您可以将其视为客户支持服务的延伸，专门处理边缘案例，例如手动身份检查、有害内容的审核、停止骚扰、处理授权和版权索赔、数据封存和其他信用卡纠纷。

- [信任与安全 101](https://www.csoonline.com/article/3206127/trust-and-safety-101.html) - 关于域及其职责的精彩介绍。

- [信任和安全到底是什么？](https://www.linkedin.com/pulse/what-heck-trust-safety-kenny-shi) - 几个真实的用例来展示 TnS 团队的作用。

<!--lint disable double-link-->

- [账单和付款清单的备忘列表：欺诈链接](https://github.com/kdeldycke/awesome-billing#fraud) - 专门用于计费和支付欺诈管理的部分，来自我们的姊妹 Git 仓库。

<!--lint enable double-link-->

### 用户身份

大多数企业不会收集客户的身份信息来创建用户档案以出售给第三方，不会。但你仍然必须这样做：当地法律要求在 ["了解你的客户" (Know You Customer KYC)](https://en.wikipedia.org/wiki/Know_your_customer) 的大旗下跟踪合同关系。

- [身份法则](https://www.identityblog.com/stories/2005/05/13/TheLawsOfIdentity.pdf) - 虽然本文的目标是身份元系统，但它的法则在较小的范围内仍然提供了很好的见解，特别是第一条法则：总是允许用户控制并征求同意以赢得信任。

- [Uber 是如何迷路的](https://www.nytimes.com/2019/08/23/business/how-uber-got-lost.html) - “为了限制‘摩擦’，Uber 允许乘客在注册时无需提供电子邮件（很容易伪造）或电话号码以外的身份信息。 (...) 车辆被盗并被烧毁； 司机遭到殴打、抢劫，有时甚至被谋杀。 该公司坚持使用低摩擦注册系统，即使暴力事件有所增加。”

- [个人姓名匹配的比较：技术和实际问题](http://users.cecs.anu.edu.au/~Peter.Christen/publications/tr-cs-06-02.pdf) - 客户姓名匹配有很多应用，从重复数据删除到欺诈监控。

- [统计学上可能的用户名](https://github.com/insidetrust/statistically-likely-usernames) - 用于创建统计学上可能的用户名的词表，以用于用户名枚举、模拟密码攻击和其他安全测试任务。

- [Facebook 上的危险个人和组织名单](https://theintercept.com/document/facebook-dangerous-individuals-and-organizations-list-reproduced-snapshot/) - 一些团体和内容在一些司法管辖区是非法的。这是一个封锁名单的例子。

- [Ballerine](https://github.com/ballerine-io/ballerine) - 一个用于用户身份和风险管理的开源基础设施。

- [Sherlock](https://github.com/sherlock-project/sherlock) - 在社交网络中按用户名猎取社交媒体账户。

### 欺诈

作为一个在线服务提供商，你面临着欺诈、犯罪和滥用的风险。你会惊讶于人们在涉及到金钱时的聪明程度。预计你的工作流程中的任何错误或差异都会被利用来获取经济利益。

- [在 Car2Go 放宽背景调查后，其75辆车在一天内被盗。](https://web.archive.org/web/20230526073109/https://www.bloomberg.com/news/articles/2019-07-11/mercedes-thieves-showed-just-how-vulnerable-car-sharing-can-be) - 为什么背景调查有时是必要的。

- [调查异常注册](https://openstreetmap.lu/MWGGlobalLogicReport20181226.pdf) - 对 OpenStreetMap 上可疑贡献者注册的详细分析。 这份精美而高层次的报告展示了一场精心策划和定向的活动，可以作为欺诈报告的模板。

- [MIDAS：检测边缘流中的微集群异常](https://github.com/bhatiasiddharth/MIDAS) - 一种提议方法“使用恒定时间和内存检测边缘流中的微簇异常，或突然到达的可疑相似边缘组。”

- [Gephi](https://github.com/gephi/gephi) - 用于可视化和操作大型图形的开源平台。

### Moderation

任何在线社区，不仅是与游戏和社交网络相关的社区，都需要其运营商投入大量资源和精力来对其进行管理。

- [仍在登录了。AR 和 VR 可以从 MMO 中学习什么？](https://youtu.be/kgw8RLHv1j4?t=534) - “如果你主持一个在线社区，在那里人们可以伤害另一个人：你就上钩了。 如果你负担不起被骗的后果，就不要主持在线社区”。

- [你要么死于 MVP，要么活到足够长的时间来建立内容节制。](https://mux.com/blog/you-either-die-an-mvp-or-live-long-enough-to-build-content-moderation/) - "你可以通过考虑三个维度来思考这个问题的解决空间：成本、准确性和速度。还有两种方法：人类审查和机器审查。人类在其中一个维度上很出色：准确性。缺点是，人类的成本高，速度慢。机器，或称机器人，在另外两个方面很出色：成本和速度--它们要便宜得多，速度也快。但是，目标是要找到一个机器人解决方案，同时对你的需求有足够的准确性"。

- [人们的绝望和黑暗会影响到你](https://restofworld.org/2020/facebook-international-content-moderators/) - 大量的外包分包商负责管理庞大的社交网络。 这些人暴露在最坏的情况下，通常最终会患上创伤后应激障碍。

- [The Cleaners](https://thoughtmaybe.com/the-cleaners/) - 一部关于这些薪酬过低的团队删除帖子和删除帐户的纪录片。

### 威胁情报

如何检测、解密和分类攻击性的在线活动。大多数时候，这些都是由安全、网络和/或基础设施工程团队监控的。不过，这些都是技术与服务和 IAM 人员的良好资源，他们可能会被要求提供额外的专业知识来分析和处理威胁。

- [很棒的威胁情报](https://github.com/hslatman/awesome-threat-intelligence) - "威胁情报的简明定义：基于证据的知识，包括背景、机制、指标、影响和可操作的建议，涉及对资产的现有或新出现的威胁或危险，可用于为主体应对该威胁或危险的决策提供信息。"

- [SpiderFoot](https://github.com/smicallef/spiderfoot) - 一个开源的情报（OSINT）自动化工具。它与几乎所有可用的数据源集成，并使用一系列的方法进行数据分析，使这些数据易于浏览。

- [与威胁情报有关的标准](https://www.threat-intelligence.eu/standards/) - 支持威胁情报分析的开放标准、工具和方法。

- [MISP 分类法和分类](https://www.misp-project.org/taxonomies.html) - 组织有关“威胁情报，包括网络安全指标、金融欺诈或反恐信息”的信息的标签。

- [浏览器指纹识别：调查](https://arxiv.org/pdf/1905.01051.pdf) - 指纹可作为识别机器人和欺诈者的信号来源。

- [文件格式的挑战](https://speakerdeck.com/ange/the-challenges-of-file-formats) - 在某个时候，你会让用户在你的系统中上传文件。这里有一个[可疑媒体文件的语料库](https://github.com/corkami/pocs)，可以被骗子利用来绕过安全或愚弄用户。

- [SecLists](https://github.com/danielmiessler/SecLists) - 收集安全评估期间使用的多种类型的列表，收集在一个地方。列表类型包括用户名、密码、URL、敏感数据模式、模糊处理有效载荷、网络外壳等等。

- [PhishingKitTracker](https://github.com/neonprimetime/PhishingKitTracker) - 威胁行为者在网络钓鱼工具包中使用的电子邮件地址的 CSV 数据库。

- [PhoneInfoga](https://github.com/sundowndev/PhoneInfoga) - 扫描电话号码的工具，只使用免费资源。目标是首先收集标准信息，如国家、地区、运营商和任何国际电话号码的线路类型，并有非常好的准确性。然后在搜索引擎上搜索足迹，试图找到网络电话供应商或确定其所有者。

- [易混淆的同音字](https://github.com/vhf/confusable_homoglyphs) - 同音字是一种常见的网络钓鱼伎俩。

### 验证码

对付垃圾邮件的另一道防线。

- [Awesome Captcha](https://github.com/ZYSzys/awesome-captcha) - 参考所有开源的验证码库、集成、替代品和破解工具。

- [reCaptcha](https://www.google.com/recaptcha) - 当你的公司没有能力拥有一个专门的团队在互联网规模上打击机器人和垃圾邮件的时候，reCaptcha 仍然是一个有效、经济和快速的解决方案。

- [你（可能）不需要ReCAPTCHA](https://web.archive.org/web/20190611190134/https://kevv.net/you-probably-dont-need-recaptcha/) - 开始时咆哮说该服务是一个隐私的噩梦，在用户界面上也很乏味，然后列出替代方案。

- [Anti-captcha](https://anti-captcha.com) - 验证码的解决服务。

## 黑名单

防止滥用的第一道机械防线包括简单明了的拒绝列表。这是打击欺诈行为的低垂果实，但你会惊讶地发现它们仍然有效。

- [Bloom Filter](https://zh.wikipedia.org/wiki/布隆过滤器) - 非常适合这种用例，因为布隆过滤器旨在快速检查元素是否不在（大）集合中。 特定数据类型存在布隆过滤器的变体。

- [Radix 树如何使阻断 IP 的速度提高5000倍](https://blog.sqreen.com/demystifying-radix-trees/) -Radix 树可能对加快 IP 封锁名单的速度很有帮助。

### 主机名和子域

有助于识别客户，捕捉和阻止机器人群，并限制 dDOS 的影响。

- [`hosts`](https://github.com/StevenBlack/hosts) - 合并有信誉的主机文件，并将它们合并成一个统一的主机文件，删除重复的部分。

- [`nextdns/metadata`](https://github.com/nextdns/metadata) - 广泛收集安全、隐私和家长控制的清单。

- [公共后缀列表](https://publicsuffix.org) - Mozilla的公共后缀注册处，互联网用户可以（或在历史上可以）直接注册名字。

- [国家IP区块](https://github.com/herrbischoff/country-ip-blocks) - CIDR 国家层面的 IP 数据，直接来自区域互联网注册中心，每小时更新一次。

- [证书透明化子域](https://github.com/internetwache/CT_subdomains) - 每小时更新一次从证书透明度日志中收集的子域列表。

- 子域否认列表: [#1](https://gist.github.com/artgon/5366868), [#2](https://github.com/sandeepshetty/subdomain-blacklist/blob/master/subdomain-blacklist.txt), [#3](https://github.com/nccgroup/typofinder/blob/master/TypoMagic/datasources/subdomains.txt), [#4](https://www.quora.com/How-do-sites-prevent-vanity-URLs-from-colliding-with-future-features).

- [`common-domain-prefix-suffix-list.tsv`](https://gist.github.com/erikig/826f49442929e9ecfab6d7c481870700) - 前5000个最常见的域名前缀/后缀列表。

- [`hosts-blocklists`](https://github.com/notracking/hosts-blocklists) -没有更多的广告、跟踪和其他虚拟垃圾。

- [`xkeyscorerules100.txt`](https://gist.github.com/sehrgut/324626fa370f044dbca7) - NSA 的 [XKeyscore](https://zh.wikipedia.org/wiki/XKeyscore) 对TOR和其他匿名保存工具的匹配规则。

- [`pyisp`](https://github.com/ActivisionGameScience/pyisp) - IP 到 ISP 的查询库（包括 ASN）。

- [AMF网站封锁名单](https://www.amf-france.org/Epargne-Info-Service/Proteger-son-epargne/Listes-noires) - 法国官方否认与金钱有关的欺诈网站名单。

### 邮件

- [烧录机电子邮件供应商](https://github.com/wesbos/burner-email-providers) - 一个临时电子邮件提供商的列表。以及其[衍生的Python模块](https://github.com/martenson/disposable-email-domains).

- [MailChecker](https://github.com/FGRibreau/mailchecker) - 跨语言的临时（一次性/抛弃式）电子邮件检测库。

- [临时电子邮件地址域名](https://gist.github.com/adamloving/4401361) - 一次性和临时电子邮件地址的域名列表。用于过滤你的电子邮件列表，以提高打开率（向这些域名发送电子邮件可能不会被打开）。

- [`gman`](https://github.com/benbalter/gman) - "一个红宝石，用于检查一个给定的电子邮件地址或网站的所有者是否在为政府工作（又称验证政府域）。" 在你的用户群中寻找潜在的政府客户的良好资源。

- [`Swot`](https://github.com/leereilly/swot) - 与上述精神相同，但这次是为了标记学术用户。

### 保留的 ID

- [保留字的总清单](https://gist.github.com/stuartpb/5710271) - 这是你可能要考虑保留的一个一般的单词列表，在一个系统中，用户可以挑选任何名字。

- [要保留的主机名和用户名](https://ldpreload.com/blog/names-to-reserve) - 所有应限制在自动系统中注册的名字的清单。

### 诽谤

- [肮脏、顽皮、淫秽和其他坏词列表](https://github.com/LDNOOBW/List-of-Dirty-Naughty-Obscene-and-Otherwise-Bad-Words) - 来自 Shutterstock 的诽谤黑名单。

- [`profanity-check`](https://github.com/vzhou842/profanity-check) - 使用在 200k 人类标记的干净和亵渎文本字符串样本上训练的线性 SVM 模型。

## 隐私

作为用户数据的守护者，IAM 技术栈中深受隐私尊重的约束。

- [隐私增强技术决策树](https://www.private-ai.com/wp-content/uploads/2021/10/PETs-Decision-Tree.pdf) - 根据数据类型和上下文选择正确工具的流程图。

- [我们喜欢的论文：隐私](https://github.com/papers-we-love/papers-we-love/tree/master/privacy) - 通过设计提供隐私的方案的科学研究集合。

- [IRMA 认证](https://news.ycombinator.com/item?id=20144240) - 使用 [Camenisch 和 Lysyanskaya 的 Idemix](https://privacybydesign.foundation/publications/) 提供隐私友好的基于属性的身份验证和签名的开源应用程序和协议。

- [我被骗了吗？](https://haveibeenpwned.com) - 数据泄露指数。

- [软件开发人员的自动化安全测试](https://fahrplan.events.ccc.de/camp/2019/Fahrplan/system/event_attachments/attachments/000/003/798/original/security_cccamp.pdf) -第三方依赖项中的已知漏洞允许大多数隐私泄露。 下面介绍如何通过 CI/CD 的方式检测它们。

- [世界各地的电子邮件营销法规](https://github.com/threeheartsdigital/email-marketing-regulations) - 随着世界的联系越来越紧密，电子邮件营销的监管情况也变得越来越复杂。

- [世界上最大的数据泄露和黑客攻击事件](https://www.informationisbeautiful.net/visualizations/worlds-biggest-data-breaches-hacks/) - 不要成为下一个泄露客户数据的公司。

### 匿名化

作为用户数据的中央存储库，IAM 技术栈的相关人员必须防止任何业务和客户数据的泄漏。为了允许内部分析，需要进行匿名化。

- [哈希法用于匿名的虚假诱惑](https://gravitational.com/blog/hashing-for-anonymization/) - Hashing 不足以实现匿名化。但对于假名化（GDPR允许的）来说，它仍然足够好。

- [四分钱去掉匿名：公司反向散列的电子邮件地址](https://freedom-to-tinker.com/2018/04/09/four-cents-to-deanonymize-companies-reverse-hashed-email-addresses/) - "哈希的电子邮件地址可以很容易地被逆转，并与个人联系起来"。

- [为什么差异化的隐私是了不起的](https://desfontain.es/privacy/differential-privacy-awesomeness.html) - 解释[差异隐私](https://zh.wikipedia.org/wiki/差分隐私)背后的直觉，这是一个理论框架，允许在不影响保密性的情况下共享聚合数据。参见后续文章[更多细节](https://desfontain.es/privacy/differential-privacy-in-more-detail.html)和[实践方面](https://desfontain.es/privacy/differential-privacy-in-practice.html)。

- [K-匿名性：简介](https://www.privitar.com/listing/k-anonymity-an-introduction) - 一个替代性的匿名隐私模型。

- [Presidio](https://github.com/microsoft/presidio) - 语境感知、可插拔和可定制的数据保护和PII数据匿名化服务，用于文本和图像。

- [Diffix：高实用性数据库匿名化](https://aircloak.com/wp-content/uploads/apf17-aspen.pdf) - Diffix 试图提供匿名化，避免假名化并保持数据质量。[在Aircloak 用 Elixir 编写](https://elixirforum.com/t/aircloak-anonymized-analitycs/10930)，它作为分析师和未修改的实时数据库之间的一个SQL代理。

### GDPR

众所周知的欧洲隐私框架

- [GDPR Tracker](https://gdpr.eu) - 欧洲的参考网站。

- [GDPR 开发指南](https://github.com/LINCnil/GDPR-Developer-Guide) - 开发者的最佳实践。

- [GDPR – 开发人员的实用指南](https://techblog.bozho.net/gdpr-practical-guide-developers/) - 上述内容的一页摘要。

- [GDPR 文档](https://github.com/good-lly/gdpr-documents) - 供个人使用的模板，让公司遵守 "数据访问 "要求。

- [GDPR 之后的黑暗模式](https://arxiv.org/pdf/2001.02479.pdf) - 本文表明，由于缺乏 GDPR 法律的执行，黑暗模式和默示同意无处不在。

- [GDPR 执行情况跟踪](http://enforcementtracker.com) - GDPR的罚款和处罚清单。

## UX/UI

作为 IAM 技术栈的利益相关者，你将在后端实现建立注册通道和用户入职所需的大部分原语。这是客户对你的产品的第一印象，不能被忽视：你必须和前端专家一起精心设计。这里有几个指南可以帮助你打磨这种体验。

- [2020 年 SaaS 产品入职的状况](https://userpilot.com/saas-product-onboarding/) - 涵盖了用户入职的所有重要方面。

- [用户入职拆解](https://www.useronboard.com/user-onboarding-teardowns/) - 一个巨大的被解构的首次用户注册的列表。

- [发现领先公司的 UI 设计决策](https://goodui.org/leaks/) - 从泄露的截图和 A/B 测试。

- [转换优化](https://www.nickkolenda.com/conversion-optimization-psychology/#cro-tactic11) - 一组战术，以增加用户完成账户创建漏斗的机会。

- [Trello 用户入职培训](https://growth.design/case-studies/trello-user-onboarding/) - 一个详细的案例研究，很好地介绍了如何改善用户的入职。

- [改善注册/登录用户体验的11个技巧](https://learnui.design/blog/tips-signup-login-ux.html) - 关于登录表格的一些基本提示。

- [不要在登录表格上耍小聪明](http://bradfrost.com/blog/post/dont-get-clever-with-login-forms/) - 创建简单、可链接、可预测的登录表格，并与密码管理器很好地配合。

- [为什么用户名和密码在两个不同的页面上？](https://www.twilio.com/blog/why-username-and-password-on-two-different-pages) - 要同时支持SSO和基于密码的登录。现在，如果将登录漏斗分成两步，对用户来说太令人生气了，可以像Dropbox那样解决这个问题：[当你输入用户名时，会有一个AJAX请求](https://news.ycombinator.com/item?id=19174355).

- [用 HTML 属性来改善你的用户的双因素认证体验](https://www.twilio.com/blog/html-attributes-two-factor-authentication-autocomplete) - "在这篇文章中，我们将看看不起眼的 `<input>` 元素和 HTML 属性，这将有助于加快我们用户的双因素认证体验"。

- [移除密码掩码](http://passwordmasking.com) - 总结了一项学术研究的结果，该研究调查了去除密码掩码对消费者信任的影响。

- [对于那些认为 "我可以在一个周末建立 "的人，Slack 是这样决定发送通知的](https://twitter.com/ProductHunt/status/979912670970249221) - 通知是困难的。真的很难。

## 竞争分析

一堆资源，以跟踪所有在该领域经营的公司的现状和进展。

- [AWS 安全、身份与合规公告](https://aws.amazon.com/about-aws/whats-new/security_identity_and_compliance/) - 所有添加到 IAM 周边的新功能的来源。

- [GCP IAM 发布说明](https://cloud.google.com/iam/docs/release-notes) - Also of note: [身份](https://cloud.google.com/identity/docs/release-notes), [身份平台](https://cloud.google.com/identity-platform/docs/release-notes), [资源管理](https://cloud.google.com/resource-manager/docs/release-notes), [密钥服务/HSM](https://cloud.google.com/kms/docs/release-notes), [访问环境管理器](https://cloud.google.com/access-context-manager/docs/release-notes), [身份感知代理](https://cloud.google.com/iap/docs/release-notes), [数据丢失预防](https://cloud.google.com/dlp/docs/release-notes) and [安全扫描器](https://cloud.google.com/security-scanner/docs/release-notes).

- [非官方的谷歌云平台周报](https://www.gcpweekly.com) - Relevant keywords: [`IAM`](https://www.gcpweekly.com/gcp-resources/tag/iam/) and [`安全`](https://www.gcpweekly.com/gcp-resources/tag/security/).

- [DigitalOcean 账户变化日志](http://docs.digitalocean.com/release-notes/accounts/) - 关于 DO 的所有最新账户更新。

- [163 项 AWS 服务各用一行解释](https://adayinthelifeof.nl/2020/05/20/aws.html#discovering-aws) -帮助使他们巨大的服务目录变得有意义。本着同样的精神：[AWS 的简单术语](https://netrixllc.com/blog/aws-services-in-simple-terms/) & [通俗易懂的 AWS](https://expeditedsecurity.com/aws-in-plain-english/).

- [谷歌云开发者的小抄](https://github.com/gregsramblings/google-cloud-4-words#the-google-cloud-developers-cheat-sheet) - 用4个字或更少描述所有 GCP 产品。

## 历史

- [cryptoanarchy.wiki](https://cryptoanarchy.wiki) - Cypherpunks 与安全重合。这个维基汇编了有关该运动、其历史和值得注意的人/事件的信息。

## 贡献

我们永远欢迎你的贡献! 请先看一下[贡献指南](.github/contributing.md)。

## Footnotes

[标题图片](https://github.com/kdeldycke/awesome-iam/blob/main/assets/awesome-iam-header.jpg) 是基于[Ben Sweet](https://unsplash.com/@benjaminsweet).的[照片](https://unsplash.com/photos/2LowviVHZ-E)修改的。

<!--lint disable no-undefined-references-->

<a name="sponsor-def">\[0\]</a>: <a href="https://github.com/sponsors/kdeldycke">您可以通过 GitHub 赞助将您的身份和身份验证产品添加到赞助商列表中</a>。 [\[↑\]](#sponsor-ref)

<a name="intro-quote-def">\[1\]</a>: [*Poison Study*](https://www.amazon.com/dp/0778324338?&linkCode=ll1&tag=kevideld-20&linkId=0b92c3d92371bd53daca5457bdad327e&language=en_US&ref_=as_li_ss_tl) (Mira, 2007). [\[↑\]](#intro-quote-ref)
