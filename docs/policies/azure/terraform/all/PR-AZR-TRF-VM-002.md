



# Master Test ID: PR-AZR-TRF-VM-002


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vm.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-VM-002|
|eval|data.rule.vm_linux_disabled_password_auth|
|message|data.rule.vm_linux_disabled_password_auth_err|
|remediationDescription|In 'azurerm_virtual_machine' resource, make sure to set 'disable_password_authentication = true' under 'os_profile_linux_config' block to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#disable_password_authentication' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_VM_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Azure Linux Instance should not use basic authentication(Use SSH Key Instead)

***<font color="white">Description:</font>*** For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_virtual_machine', 'azurerm_windows_virtual_machine', 'azurerm_linux_virtual_machine_scale_set', 'azurerm_linux_virtual_machine']


[vm.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego
