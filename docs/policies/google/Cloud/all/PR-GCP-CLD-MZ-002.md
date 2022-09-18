



# Title: GCP Cloud DNS zones using RSASHA1 algorithm for DNSSEC key-signing


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-MZ-002

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_DNS']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dns.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-MZ-002|
|eval|data.rule.dnssec_key_rsasha1|
|message|data.rule.dnssec_key_rsasha1_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/dns/docs/reference/v1/managedZones' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_MZ_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies the GCP Cloud DNS zones which are using the RSASHA1 algorithm for DNSSEC key-signing. DNSSEC is a feature of the Domain Name System that authenticates responses to domain name lookups and also prevents attackers from manipulating or poisoning the responses to DNS requests. So the algorithm used for key signing should be recommended one and it should not be weak.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['cloud']|



[dns.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/dns.rego
