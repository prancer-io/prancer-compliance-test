



# Title: Azure Security Center should have pricing tier configured to 'standard'


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-ASC-001

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([pricing.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-ASC-001|
|eval|data.rule.pricing|
|message|data.rule.pricing_err|
|remediationDescription|Make sure you are following the ARM template guidelines for pricing by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.security/pricings' target='_blank'>here</a>|
|remediationFunction|PR_AZR_ARM_ASC_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Selecting the standard pricing tier will enable threat detection for networks and virtual systems by providing threat intelligence, anomaly detection, and behavior analytics in Azure Security Center.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'ISO 27001']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.security/pricings']


[pricing.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/pricing.rego
