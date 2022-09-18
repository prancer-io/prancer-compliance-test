



# Title: Azure Security Center should have pricing tier configured to 'standard'


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-ASC-001

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_300']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([pricing.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-ASC-001|
|eval|data.rule.pricing|
|message|data.rule.pricing_err|
|remediationDescription|To change the policy using the Azure Portal, follow these steps:<br>1. Log in to the Azure Portal at https://portal.azure.com.<br>2. Navigate to the Azure Security Center.<br>3. Select Security policy blade.<br>4. To alter the the security policy for a subscription, click Edit Settings.<br>5. Select Pricing tier blade.<br>6. Select Standard.<br>7. Select Save.|
|remediationFunction|PR_AZR_CLD_ASC_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Selecting the standard pricing tier will enable threat detection for networks and virtual systems by providing threat intelligence, anomaly detection, and behavior analytics in Azure Security Center.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['CIS', 'ISO 27001']|
|service|['Security']|



[pricing.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/pricing.rego
