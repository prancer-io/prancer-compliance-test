



# Title: GCP Cloud DNS has DNSSEC disabled


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-MZ-001

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_DNS']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dns.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-MZ-001|
|eval|data.rule.dnssec_state|
|message|data.rule.dnssec_state_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/dns/docs/reference/v1/managedZones' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_MZ_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP Cloud DNS which has DNSSEC disabled. Domain Name System Security Extensions (DNSSEC) adds security to the Domain Name System (DNS) protocol by enabling DNS responses to be validated. Attackers can hijack the process of domain/IP lookup and redirect users to a malicious site through DNS hijacking and man-in-the-middle attacks. DNSSEC helps mitigate the risk of such attacks by cryptographically signing DNS records. As a result, it prevents attackers from issuing fake DNS responses that may misdirect browsers to fake websites.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['cloud']|



[dns.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/dns.rego
