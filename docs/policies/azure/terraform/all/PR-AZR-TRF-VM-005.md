



# Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-VM-005

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vm.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-VM-005|
|eval|data.rule.vm_type_linux_scale_set_disabled_password_auth|
|message|data.rule.vm_type_linux_scale_set_disabled_password_auth_err|
|remediationDescription|In 'azurerm_linux_virtual_machine_scale_set' resource, make sure to set 'disable_password_authentication = true' to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine_scale_set#disable_password_authentication' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_VM_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_virtual_machine', 'azurerm_windows_virtual_machine', 'azurerm_linux_virtual_machine_scale_set', 'azurerm_linux_virtual_machine']


[vm.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego
