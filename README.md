# Penetration Testing Framework
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

## Attack 2: Broken Authentication
### Reports: 
### [B.A Case 1](https://medium.com/@prajwalpatil453/how-i-found-my-first-p1-bug-705b6ba5e3e2)
📝: A basic case of bruteforcing credentials. Tedious (because of recon and then individually attacking each subdomain) but rewarding task.

## Attack 3: Cross-site Scripting
### Reports: 
### [XSS Case 1](https://medium.com/@gg20205959/discovery-of-reflected-xss-vulnerability-on-a-global-car-website-2-ddfc7ba9f67d)
📝: An interesting XSS case where payload is injected through declaration of a variable.
