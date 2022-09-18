



# Title: Custom Role Definition should not create subscription owner role


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-ARD-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([roles.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-ARD-001|
|eval|data.rule.no_cusRtom_subs_owner_role_created|
|message|data.rule.no_custom_subs_owner_role_created_err|
|remediationDescription|In 'azurerm_role_definition' resource, make sure 'permissions' blocks 'actions' array dont have '*' as entry to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_definition#actions' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_ARD_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Manages a custom Role Definition, used to assign Roles to Users/Principals. This policy will identify custom role definition which has action permission set to subscription owner and alert if exist.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_role_definition']


[roles.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/roles.rego
