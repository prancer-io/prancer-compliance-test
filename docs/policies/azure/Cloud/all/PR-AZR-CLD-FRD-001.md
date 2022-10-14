



# Title: Azure frontDoors should have configured with WAF policy with Default Rule Set 1.0/1.1 for proactive protection against CVE-2021-44228 exploit


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-FRD-001

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_220', 'AZRSNP_502']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([frontdoors.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-FRD-001|
|eval|data.rule.frontdoors_has_drs_configured|
|message|data.rule.frontdoors_has_drs_configured_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-tuning#understanding-waf-logs' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_FRD_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It is recommended to enable WAF policy with Default Rule Set 1.0/1.1 on Front Door deployments to immediately avail of additional protection from log4j Remote Command Execution. details at https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Networking']|



[frontdoors.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/frontdoors.rego
