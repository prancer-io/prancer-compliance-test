



# Master Test ID: PR-AZR-TRF-AFA-003


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([functionapp.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-AFA-003|
|eval|data.rule.functionapp_enabled_latest_http2_protocol|
|message|data.rule.functionapp_enabled_latest_http2_protocol_err|
|remediationDescription|In 'azurerm_function_app' resource, set 'http2_enabled = true' under 'site_config' to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app#http2_enabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_AFA_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure that 'HTTP Version' is the latest, if used to run the Function app

***<font color="white">Description:</font>*** Periodically, newer versions are released for HTTP either due to security flaws or to include additional functionality. Using the latest HTTP version for web apps to take advantage of security fixes, if any, and/or new functionalities of the newer version. Currently, this policy only applies to Linux web apps.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_function_app']


[functionapp.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/functionapp.rego
