



# Title: Azure Linux Instance should not allow extension operation


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-VM-006

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vm.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-VM-006|
|eval|data.rule.vm_type_linux_disabled_extension_operation|
|message|data.rule.vm_type_linux_disabled_extension_operation_err|
|remediationDescription|In 'azurerm_linux_virtual_machine' resource, make sure to set 'allow_extension_operations = false' to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine#allow_extension_operations' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_VM_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** For security purpose, linux vm extension operation should be disabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_virtual_machine', 'azurerm_windows_virtual_machine', 'azurerm_linux_virtual_machine_scale_set', 'azurerm_linux_virtual_machine']


[vm.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego
