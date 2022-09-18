



# Title: Azure Firewall Premium should be configured with both IDPS Alert & Deny mode and TLS inspection enabled for proactive protection against CVE-2021-44228 exploit


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-AFW-001

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_225', 'AZRSNP_230']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([azure_firewalls.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-AFW-001|
|eval|data.rule.azure_firewall_configured_with_idpc_and_tls_inspection|
|message|data.rule.azure_firewall_configured_with_idpc_and_tls_inspection_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/firewall/premium-features' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_AFW_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Azure Firewall Premium has enhanced protection from the Log4j RCE CVE-2021-44228 vulnerability and exploit. Azure Firewall premium IDPS (Intrusion Detection and Prevention System) provides IDPS inspection for all east-west traffic and outbound traffic to internet. details at https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Networking']|



[azure_firewalls.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/azure_firewalls.rego
