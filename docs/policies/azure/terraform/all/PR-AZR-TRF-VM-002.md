



# Master Test ID: PR-AZR-TRF-VM-002


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(vm.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-VM-002|
|eval: |data.rule.vm_linux_disabled_password_auth|
|message: |data.rule.vm_linux_disabled_password_auth_err|
|remediationDescription: |In 'azurerm_virtual_machine' resource, make sure to set 'disable_password_authentication = true' under 'os_profile_linux_config' block to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#disable_password_authentication' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_VM_002.py|


severity: High

title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)

description: For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |[]|
|service: |['terraform']|


resourceTypes: ['azurerm_virtual_machine', 'azurerm_windows_virtual_machine', 'azurerm_linux_virtual_machine_scale_set', 'azurerm_linux_virtual_machine']


[file(vm.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego
