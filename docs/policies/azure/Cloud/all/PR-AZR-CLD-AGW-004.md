



# Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-AGW-004

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_221']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([applicationgateways.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-AGW-004|
|eval|data.rule.frontendPublicIPConfigurationsDisabled|
|message|data.rule.frontendPublicIPConfigurationsDisabled_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/application-gateway/configuration-front-end-ip' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_AGW_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['Networking']|



[applicationgateways.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/applicationgateways.rego
