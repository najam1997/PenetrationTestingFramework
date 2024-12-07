# Penetration Testing Writeups
This repository contains references to all the relevant reports w.r.t Owasp Top 10 vulnerabilities and many more.    
    Each attack and report will be provided a use case against which it'll be applicable to save time for viewers.

**Key:**  
   📝: Description

## Attack 1: Broken Access Control
### Reports: 
### [IDOR Case 1](https://prateeksrivastavaa.medium.com/zomatoooo-idor-in-saved-payments-f8c014879741)
📝: A basic IDOR in zomato application which the attacker could use to view saved paymed info of other users through id manipulation.

### [IDOR Case 2](https://medium.com/@zack0x01_/how-i-found-2-idors-on-my-phone-and-made-1-500-8b088f5b28db)
📝: A basic IDOR on an API endpoint which the attacker can use to extract PII through id manipulation and the author used automation script to develop an interesting POC.

### [IDOR Case 3](https://medium.com/@0x_xnum/idor-leads-to-account-takeover-of-all-users-ato-27af312c8481)
📝: An interesting case of IDOR, that used timestamp (which can be manipulated) as the second source of validation but failed to validate authorization token, thus, leading to account takeover.

### [IDOR Case 4](https://medium.com/@melguerdawi/idor-lead-to-data-leak-c5107094f9ca)
📝: A basic IDOR on an API endpoint through method manipulation.

### [IDOR Case 5](https://medium.com/@ozomarzu/from-javascript-analysis-to-uuid-pattern-exploration-revealed-a-critical-idor-5c526451e7ec)
📝: A simple case of IDOR throuh UUID manipulation. The API endpoint was retrieved through a hidden JS file using an interesting recon methodology.

### [IDOR Case 5](https://medium.com/@hawkeye69669/breaking-boundaries-discovering-session-invalidation-failures-in-user-roles-84711777f9f2)
📝: A simple case, where a user who is admin is downgraded from the role but still has the rights to perform user deletion.

### [IDOR Case 6](https://medium.com/@noureldin1042/single-endpoint-leads-to-two-bounties-400-7dd96cf601c7)
📝: A couple of simple BAC vulnerabilities on API endpoints, one was the token still being active even after the user's removal. Second was request parameter manipulation when generating the token for additional rights.

### [IDOR Case 7](https://medium.com/@omdubey170/broken-access-control-vulnerability-in-an-order-management-system-8a1097b03926)
📝: A basic case of IDOR where when the JWT token was removed, the API was giving all the user's data.

### [IDOR Case 8](https://ro0od.medium.com/smart-recon-to-pwn-the-panel-a23b0b9466bb)
📝: 

### [IDOR Case 9](https://c0nqr0r.medium.com/idor-and-broken-access-control-risking-private-data-exposure-dd808412ed13)
📝: A simple case of IDOR to retrieve background ID and then exploit broken access control to view reports. The enumeration in this report is good.

### [IDOR Case 10](https://0xmatrix.medium.com/idor-exploit-gaining-unauthorized-control-over-users-shopping-baskets-122650091cf5)
📝: Interesting case of extracting sensitive info through GraphQL for IDOR.

### [IDOR Case 10](https://medium.com/@suppaboy/how-a-unique-combination-opened-the-door-to-an-idor-f44a3efe51e8)
📝:

### https://medium.com/@abhinavsingwal/bug-report-broken-access-control-in-google-photos-d9c10ca8c472
### https://medium.com/@mahdisalhi0500/finding-my-first-bug-the-power-of-understanding-website-logic-%EF%B8%8F-4197dd08cf29
### https://appomni.com/ao-labs/microsoft-power-pages-data-exposure-reviewed/
### https://medium.com/@l_s_/honey-you-left-the-apis-open-again-c382a3a2d917
### https://hackerone.com/reports/2534458
### https://mo9khu93r.medium.com/how-i-bypassed-rate-limit-on-login-b600b15158ef
### https://medium.com/@Ibrahimsec/how-i-found-an-idor-that-led-to-session-hijacking-9875a6bdb482
### https://medium.com/@srilakivarma/how-i-found-rce-vulnerability-in-an-api-endpoint-7cd02d77a239

## Attack 2: Broken Authentication
### Reports: 
### [B.A Case 1](https://medium.com/@prajwalpatil453/how-i-found-my-first-p1-bug-705b6ba5e3e2)
📝: A basic case of bruteforcing credentials. Tedious (because of recon and then individually attacking each subdomain) but rewarding task.

### [B.A Case 2](https://medium.com/@bughunt789/forget-password-otp-flaw-lead-to-account-takeover-b3f2b847952b)
📝: OTP bypass via response manipulation.

### [B.A Case 3](https://medium.com/@hohky_/jwt-authentication-bypass-leads-to-admin-control-panel-dfa6efcdcbf5)
📝: A simple case of broken JWT mechanism where using the JSON Web Tokens extension in Burp, the attacker could change the **uid** of the user to bump their role to admin.

### [B.A Case 3](https://medium.com/@khode4li/eyeglass-adventures-from-typos-to-admin-access-a-hackers-tale-0a3149acd6e9)
📝: A simple case of parameter manipulation in response to bump the user's role to admin.

### [B.A Case 4](https://medium.com/@muhammedgalal66/oauth-account-takeover-ato-vulnerability-via-email-manipulation-94e0e942bcb8)
📝: A case of improperly implemented Google Oauth in an app, that could be leveraged to generate login link for any email id.

### [B.A Case 5](https://medium.com/@mos693570/0-click-ato-via-reset-password-weird-scenario-9afa4a88e413)
📝: A simple case of password reset token working in the case of other emails as well due to which attacker is successfully able to change the password of the victim.

### [B.A Case 6](https://rikeshbaniya.medium.com/abusing-auto-mail-responders-to-access-internal-workplaces-04fcc8ba2c99)
📝: A very interesting case of emailing the victim through automated email in Figma and signing them up.

### [B.A Case 7](https://medium.com/@mos693570/0-click-ato-via-reset-password-weird-scenario-9afa4a88e413)
📝: A simple case of change victim's password through forgot password link where the token wasn't verifying. 

### [B.A Case 8](https://medium.com/@ProwlSec/the-oauth-oversight-when-configuration-errors-turn-into-account-hijacks-5ed1f9c83d16)
📝: A simple case of oauth bypass where if the email is signed up manually, it'll log you in through Oauth as well.

### [B.A Case 9](https://mo9khu93r.medium.com/discovered-a-unique-email-verification-bypass-47bb1e955a13)
📝: A simple yet interesting case of Email Verification bypass where CSRF token and Session ID were used.

### https://medium.com/@cvjvqmmsm/easy-bug-how-i-uncovered-and-re-exploited-a-resolved-vulnerability-from-a-disclosed-report-ab2211a98b7b
### https://medium.com/@raxomara/logic-flaw-user-account-lockout-8865c622cef0
### https://rikeshbaniya.medium.com/authorization-bypass-due-to-cache-misconfiguration-fde8b2332d2d
### https://blog.voorivex.team/oauth-non-happy-path-to-ato
### https://0d-amr.medium.com/account-takeover-how-i-gained-access-to-any-user-account-through-a-simple-registration-flaw-96f9f6bdc0ae
### https://medium.com/@mrcix/bypass-of-username-policy-breaking-the-rules-with-a-simple-trick-fcf7ce97925c
### https://hamzadzworm.medium.com/critical-account-takeover-via-interesting-logic-issue-6e5f4ee86c5b
### https://medium.com/@prakashchand72/authentication-bypass-mfa-account-takeover-32166aedb3b9
### https://1-day.medium.com/an-idor-and-auth-bypass-that-led-to-mass-account-takeover-ksfe-db04cec8d730
### https://aungpyaekoko.medium.com/two-factor-authentication-bypass-50-5b397e68cfed
### https://freedium.cfd/https://medium.com/@sharp488/critical-account-takeover-mfa-auth-bypass-due-to-cookie-misconfiguration-3ca7d1672f9d

## Attack 3: Cross-site Scripting
### Reports: 
### [XSS Case 1](https://medium.com/@gg20205959/discovery-of-reflected-xss-vulnerability-on-a-global-car-website-2-ddfc7ba9f67d)
📝: An interesting XSS case where payload is injected through declaration of a variable.

### [XSS Case 2](https://infosecwriteups.com/persistent-xss-vulnerability-on-microsoft-bings-video-indexing-system-a46db992ac7b)
📝: A stored XSS was found of bing when uploading a video on it. The most interesting part was, a simple **<script>** tag was used to trigger
the payload.

### [XSS Case 3](https://medium.com/@dsmodi484/alert-reflected-xss-detected-57850c34a61e)
📝: An interesting case of character whitelist bypass to achieve RXSS.

### [XSS Case 3](https://7odamoo.medium.com/account-takeover-for-google-sso-users-b50f99b49f0d)
📝: 

### [XSS Case 3](https://medium.com/@sgzldmrc/xss-ve-context-%C3%B6rnekleri-6ba2bc976c1f)
📝: 

### [XSS Case 3](https://blog.bhuwanbhetwal.com.np/breaking-in-how-rxss-and-sqli-can-lead-to-full-account-takeover-and-database-access)
📝: 

### https://cybersecuritywriteups.com/how-an-html-injection-vulnerability-in-samsung-emails-led-to-a-payday-3dcfccc12a36
### https://xsametyigit.medium.com/3-reflected-xss-in-one-program-c50469c6d522
### https://medium.com/@ao64400225/an-unusual-way-to-find-xss-injection-in-one-minute-9ed2c7e2a848
### https://cybersecuritywriteups.com/how-did-i-get-my-first-collaboration-bounty-of-1000-dc64ec02a6c7
### https://medium.com/@0xw01f/they-ignored-my-bug-report-but-fixed-it-silently-my-experience-with-enhancv-a8ffe5e3e790
### https://medium.com/@0xbugatti/how-hidden-3xxss-got-revealed-b42f041d36f6
### https://medium.com/@ziadsakr/xss-in-registration-form-a-bug-bounty-success-6fb9450b0e66
### https://wgetkb.medium.com/unique-xss-earned-me-a-bounty-b7156c36fd32
### https://medium.com/@pedbap/wormable-xss-www-bing-com-7d7cb52e7a12
### https://bug-abdelilah.medium.com/account-takover-of-an-online-casino-e13987835266
### https://medium.com/@xrypt0/how-did-i-easily-find-stored-xss-at-apple-and-earn-5000-3aadbae054b2
### https://medium.com/@mohanad9837/here-is-how-i-got-my-first-bounty-78c18da7feeb
### https://cyb3rc4t.medium.com/stored-xss-privilege-escalation-in-profile-field-private-program-2bdde55e34b2
### https://cyb3rc4t.medium.com/hidden-reflected-xss-via-android-application-in-vdp-68f4210196f1
### https://medium.com/@chor4o/exploring-an-xss-vulnerability-in-a-hidden-parameter-099f8916cb9a
### https://f4t7.medium.com/xss-in-hidden-input-field-1b98a5fece26
### https://medium.com/@snoopy101/1000-for-a-simple-stored-xss-8be7083a7c2d

## Attack 4: Cross-site Request Forgery
### Reports: 
### [CSRF Case 1](https://infosecwriteups.com/csrf-bypass-using-domain-confusion-leads-to-ato-ac682dd17722)
📝: An

### [CSRF Case 2](https://blog.bhuwanbhetwal.com.np/csrf-post-body-param-reflection-post-based-xss-a-brainfuck))
📝: An

### [CSRF Case 2](https://hackerone.com/reports/1890310)
📝: An

### https://medium.com/@0ldRASHED/csrf-lead-to-account-takeover-with-1-click-f9c0c607612f
### https://medium.com/@iPsalmy/exploiting-csrf-and-otp-reuse-how-weak-token-management-enables-password-reset-attacks-leading-to-c2f6b914f398

## Attack 5: Information Disclosure
### Reports: 
### [I.D Case 1](https://theabhishekbhujang.medium.com/exposing-a-data-leak-vulnerability-my-journey-to-discovery-7be93ce2c5b0)
📝: An

### [I.D Case 2](https://medium.com/@srishavinkumar/p3-medium-how-i-gain-access-to-nasas-internal-workspace-d0896fee563c)
📝: A simple case of Information Disclosure through google dorks.

### [I.D Case 3](https://medium.com/@s1renhead/keyed-in-compromising-an-entire-organization-through-their-api-2ed6cb54eec5)
📝: A simple case of API Key disclosure but interesting case of privelege escalation through recon.

### https://sushantdhopat.medium.com/i-just-doing-recon-on-bugcrowd-public-program-and-was-trying-to-find-an-information-disclosure-on-99939e92732d
### https://freedium.cfd/https://infosecwriteups.com/how-i-earned-650-using-just-recon-a-bug-hunters-success-story-4d78788e46a5
### https://cybersecuritywriteups.com/unveiling-a-critical-bug-in-one-of-the-worlds-largest-banks-my-barclays-story-34a9fb5f5140
### https://medium.com/@mrcix/sensitive-data-exposure-in-a-moodle-config-file-648ca3d54676
### https://rhashibur75.medium.com/how-i-got-critical-p2-bug-on-google-vrp-165017145af8
### https://infosecwriteups.com/how-sensitive-information-disclosure-can-lead-to-account-takeover-vulnerabilities-4d18d2a3711d
### https://infosecwriteups.com/critical-security-findings-at-the-university-of-cambridge-a-methodology-for-detecting-exposed-02df63976710
### https://medium.com/@coyemerald/how-i-found-a-critical-p1-bug-in-one-of-googles-products-with-google-1c11352eba6f
### https://freedium.cfd/https://medium.com/@alishoaib5929/bug-bounty-series-found-an-api-key-by-just-running-simple-tool-c308a3a89ad8
### https://medium.com/@kirtanpatel9111998/how-i-was-able-to-find-easy-p1-just-by-doing-recon-fdef0c689362
### https://infosecwriteups.com/from-recon-via-censys-and-dnsdumpster-to-getting-p1-by-login-using-weak-password-password-504e617956ce
### https://sapt.medium.com/bypassing-403-protection-to-get-pagespeed-admin-access-822fab64c0b3

## Attack 6: Denial of Service
### Reports: 
### [DOS Multiple Cases](https://www.youtube.com/watch?v=b7WlUofPJpU)
📝: In this Defcon talk by Lupin, he discusses multiple types of DOS from easy to complex exploits.

## Attack 7: Dependency Confusion
### Reports: 
### [Case 1](https://medium.com/@omargamal4em/dependency-confusion-unleashed-how-one-misconfiguration-can-compromise-an-entire-system-e0df2a26c341)
📝: A simple case of D.C where an npm package was found in recon that was claimable. The POC is easy to understand.

### Reports: 
### [Case 2](https://mchklt.medium.com/rce-via-dependency-confusion-a-real-world-attack-on-unclaimed-npm-packages-11f9043d00d5)
📝: 

## Attack 8: Injection
### Reports: 
### [Template Case 1](https://rikeshbaniya.medium.com/tale-of-zendesk-0-day-and-a-potential-25k-bounty-61bcf9c5dc06)
📝: An interesting case of Template injection in zendesk in the subject body of the form.

https://medium.com/@MianHammadx0root/exploiting-ssti-vulnerability-on-an-e-commerce-website-a-professional-walkthrough-6cc95afb2b38

### [File Uploade Case 1](https://medium.com/@domenicoveneziano/hidden-in-plain-sight-uncovering-rce-on-a-forgotten-axis2-instance-86ddc91f1415)
📝: A simple case of Command Injection via File Upload.

### [File Uploade Case 1](https://medium.com/@gheeX/how-i-found-an-sql-injection-in-coupon-code-f31d6eb1a720)
📝:

### https://blog.voorivex.team/20300-bounties-from-a-200-hour-hacking-challenge
### https://freedium.cfd/https://doordiefordream.medium.com/how-i-got-50euro-bounty-71dcf4c6e335
### https://c0nqr0r.medium.com/error-based-sql-injection-with-waf-bypass-manual-exploit-100-bab36b769005
### https://p4n7h3rx.medium.com/file-upload-upload-intercept-exploit-b5aa18cb8e9d
### https://sushant-kamble.medium.com/account-takeover-chained-to-host-header-injection-7fef5a0c310a
### https://infosecwriteups.com/how-i-leveraged-html-injection-to-create-an-account-using-someone-elses-email-b80f83ab9465
### https://medium.com/@m_kasim2/exploiting-os-command-injection-a-real-world-scenario-4a2db1733137
### https://medium.com/@pawarpushpak36/bug-bounty-chronicles-exploiting-the-put-method-for-remote-code-execution-rce-c2782bea61da
### https://medium.com/@srilakivarma/how-i-found-rce-vulnerability-in-an-api-endpoint-7cd02d77a239
### https://freedium.cfd/https://th3m4rk5man.medium.com/bypassed-an-admin-panel-using-sql-payloads-37529331aa1c
### https://medium.com/@srilakivarma/how-i-found-rce-vulnerability-in-an-api-endpoint-7cd02d77a239
### https://medium.com/@red.whisperer/from-file-upload-to-lfi-a-journey-to-exploitation-02ab5e1a7d0a
### https://medium.com/@srilakivarma/the-hidden-flaw-sql-injection-in-a-file-download-api-endpoint-65b3819d168d

## Attack 9: Subdomain Takeover
### Reports: 
### [S.T Case 1](https://medium.com/@D2Cy/how-i-found-a-subdomain-takeover-bug-and-earned-a-500-bounty-0edc139fe994)
📝: A simple case of subdomain takeover of the domain discovered through recon.

### [S.T Case 1](https://medium.com/@whitedevil127/4o4-not-found-bounty-d784a69dab7f)
📝: A simple case of subdomain takeover with interesting recon.

### https://xsametyigit.medium.com/heroku-subdomain-takeover-39b9f1ce7c4c

## Attack 10: Open-Redirect 
### Reports: 
### [O.R case 1](https://cyb3rc4t.medium.com/account-takeover-via-hidden-parameters-in-bbp-f65ce42ca96f)
📝: ATO via open redirect. The recon is simple and effective.
### https://freedium.cfd/https://osintteam.blog/20-open-redirect-bugs-in-few-minutes-c9fdabf75642
### https://infosecwriteups.com/story-of-a-1000-open-redirect-1405fb8a0e7a
### https://hackerone.com/reports/1479889
### https://keroayman77.medium.com/how-i-get-open-redirect-vulnerability-in-bbp-6006e5a34602

## Attack 11: Race-Condition
### Reports: 
### [R.C case 1](https://medium.com/@manibharathi.b/breaking-the-rules-how-a-race-condition-allowed-me-to-bypass-the-limits-by-mani-d6840746a04e)
📝: A simple case of Race Condition through executing multiple requests at the same time.
### https://medium.com/@Nightblood/a-beautiful-bug-interesting-url-scheme-bypass-race-condition-61109771a250

## Attack 11: SSRF
### Reports: 
### [R.C case 1](https://mokhansec.medium.com/bypassing-filters-ssrf-exploitation-via-dns-rebinding-with-just-1-in-30-successful-requests-2fdc3a9cfd7d)
📝: 
### https://infosecwriteups.com/ssrf-to-internal-data-access-via-pdf-print-feature-b8e6a912844a
### https://medium.com/@gguzelkokar.mdbf15/from-wayback-machine-to-aws-metadata-uncovering-ssrf-in-a-production-system-within-5-minutes-2d592875c9ab

## Attack 12: HTTP Request Smuggling
### Reports:
### https://medium.com/@bugbounty_learners/today-how-to-get-500-bounty-on-hackerone-p3-345fa44f76a3

## Android 
### https://infosecwriteups.com/how-i-hacked-billion-android-users-social-and-3rd-party-account-a-story-about-5000-bug-54d8b6ce75df
### https://medium.com/@amolbhavar/how-i-get-1000-bounty-for-discovering-account-takeover-in-android-application-3c4f54fbde39
