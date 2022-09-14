



# Master Test ID: PR-AZR-TRF-VM-007


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(vm.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-VM-007|
|eval: |data.rule.vm_type_windows_disabled_extension_operation|
|message: |data.rule.vm_type_windows_disabled_extension_operation_err|
|remediationDescription: |In 'azurerm_windows_virtual_machine' resource, make sure to set 'allow_extension_operations = false' to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/windows_virtual_machine#allow_extension_operations' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_VM_007.py|


severity: Medium

title: Azure Windows Instance should not allow extension operation

description: For security purpose, windows vm extension operation should be disabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |[]|
|service: |['terraform']|


resourceTypes: ['azurerm_virtual_machine', 'azurerm_windows_virtual_machine', 'azurerm_linux_virtual_machine_scale_set', 'azurerm_linux_virtual_machine']


[file(vm.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego
