



# Title: Ensure that admin user is disabled for Container Registry


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-ACR-002

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_224']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([registry.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-ACR-002|
|eval|data.rule.adminUserDisabled|
|message|data.rule.adminUserDisabled_err|
|remediationDescription|Azure Portal:<br>1. navigating to Azure container registry<br>2. select Access keys under SETTINGS<br>3. Disable under Admin user.|
|remediationFunction|PR_AZR_CLD_ACR_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The value that indicates whether the admin user is enabled. Each container registry includes an admin user account, which is disabled by default. You can enable the admin user and manage its credentials in the Azure portal, or by using the Azure CLI or other Azure tools. All users authenticating with the admin account appear as a single user with push and pull access to the registry. Changing or disabling this account disables registry access for all users who use its credentials.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Containers']|



[registry.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/registry.rego
