



# Title: Ensure that admin user is disabled for Container Registry


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-ACR-002

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([registry.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-ACR-002|
|eval|data.rule.adminUserDisabled|
|message|data.rule.adminUserDisabled_err|
|remediationDescription|In Resource of type "Microsoft.containerregistry/registries" make sure properties.adminUserEnabled is set to "Disabled" .<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_ACR_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The value that indicates whether the admin user is enabled. Each container registry includes an admin user account, which is disabled by default. You can enable the admin user and manage its credentials in the Azure portal, or by using the Azure CLI or other Azure tools. All users authenticating with the admin account appear as a single user with push and pull access to the registry. Changing or disabling this account disables registry access for all users who use its credentials.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.containerregistry/registries']


[registry.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/registry.rego
