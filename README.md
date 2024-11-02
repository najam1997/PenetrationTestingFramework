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

## Attack 3: Cross-site Scripting
### Reports: 
### [XSS Case 1](https://medium.com/@gg20205959/discovery-of-reflected-xss-vulnerability-on-a-global-car-website-2-ddfc7ba9f67d)
📝: An interesting XSS case where payload is injected through declaration of a variable.

### [XSS Case 2](https://infosecwriteups.com/persistent-xss-vulnerability-on-microsoft-bings-video-indexing-system-a46db992ac7b)
📝: A stored XSS was found of bing when uploading a video on it. The most interesting part was, a simple **<script>** tag was used to trigger
the payload.

## Attack 4: Cross-site Request Forgery
### Reports: 
### [CSRF Case 1](https://infosecwriteups.com/csrf-bypass-using-domain-confusion-leads-to-ato-ac682dd17722)
📝: An

### [CSRF Case 2]()
📝: An

## Attack 5: Information Disclosure
### Reports: 
### [I.D Case 1](https://theabhishekbhujang.medium.com/exposing-a-data-leak-vulnerability-my-journey-to-discovery-7be93ce2c5b0)
📝: An

### [I.D Case 1](https://medium.com/@srishavinkumar/p3-medium-how-i-gain-access-to-nasas-internal-workspace-d0896fee563c)
📝: A simple case of Information Disclosure through google dorks.

## Attack 6: Denial of Service
### Reports: 
### [DOS Multiple Cases](https://www.youtube.com/watch?v=b7WlUofPJpU)
📝: In this Defcon talk by Lupin, he discusses multiple types of DOS from easy to complex exploits.

## Attack 7: Dependency Confusion
### Reports: 
### [Case 1](https://medium.com/@omargamal4em/dependency-confusion-unleashed-how-one-misconfiguration-can-compromise-an-entire-system-e0df2a26c341)
📝: A simple case of D.C where an npm package was found in recon that was claimable. The POC is easy to understand.

## Attack 8: Injection
### Reports: 
### [Template Case 1](https://rikeshbaniya.medium.com/tale-of-zendesk-0-day-and-a-potential-25k-bounty-61bcf9c5dc06)
📝: An interesting case of Template injection in zendesk in the subject body of the form.

### [File Uploade Case 1](https://medium.com/@domenicoveneziano/hidden-in-plain-sight-uncovering-rce-on-a-forgotten-axis2-instance-86ddc91f1415)
📝: A simple case of Command Injection via File Upload.

## Attack 9: Subdomain Takeover
### Reports: 
### [S.T Case 1](https://medium.com/@D2Cy/how-i-found-a-subdomain-takeover-bug-and-earned-a-500-bounty-0edc139fe994)
📝: A simple case of subdomain takeover of the domain discovered through recon.
