



# Title: GCP Cloud DNS zones using RSASHA1 algorithm for DNSSEC zone-signing


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-MZ-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dns.v1.managedzone.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-MZ-003|
|eval|data.rule.dnssec_zone_rsasha1|
|message|data.rule.dnssec_zone_rsasha1_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies the GCP Cloud DNS zones which are using the RSASHA1 algorithm for DNSSEC zone-signing. DNSSEC is a feature of the Domain Name System that authenticates responses to domain name lookups and also prevents attackers from manipulating or poisoning the responses to DNS requests. So the algorithm used for key signing should be recommended one and it should not be weak.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_dns_managed_zone']


[dns.v1.managedzone.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/dns.v1.managedzone.rego
