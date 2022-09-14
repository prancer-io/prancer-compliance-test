



# Master Test ID: PR-AZR-TRF-ARD-001


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(roles.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-ARD-001|
|eval: |data.rule.no_cusRtom_subs_owner_role_created|
|message: |data.rule.no_custom_subs_owner_role_created_err|
|remediationDescription: |In 'azurerm_role_definition' resource, make sure 'permissions' blocks 'actions' array dont have '*' as entry to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_definition#actions' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_ARD_001.py|


severity: High

title: Custom Role Definition should not create subscription owner role

description: Manages a custom Role Definition, used to assign Roles to Users/Principals. This policy will identify custom role definition which has action permission set to subscription owner and alert if exist.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |[]|
|service: |['terraform']|


resourceTypes: ['azurerm_role_definition']


[file(roles.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/roles.rego
