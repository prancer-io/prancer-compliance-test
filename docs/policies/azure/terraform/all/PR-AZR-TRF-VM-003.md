



# Master Test ID: PR-AZR-TRF-VM-003


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(vmextensions.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-VM-003|
|eval: |data.rule.vm_protection|
|message: |data.rule.vm_protection_err|
|remediationDescription: |In 'azurerm_virtual_machine_extension' resource, set type = 'iaasantimalware' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine_extension#type' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_VM_003.py|


severity: High

title: Azure Virtual Machine should have endpoint protection installed

description: This policy identifies Azure Virtual Machines (VMs) that do not have endpoint protection installed. Installing endpoint protection systems (like Antimalware for Azure) provides for real-time protection capability that helps identify and remove viruses, spyware, and other malicious software. As a best practice, install endpoint protection on all VMs and computers to help identify and remove viruses, spyware, and other malicious software.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |[]|
|service: |['terraform']|


resourceTypes: ['azurerm_virtual_machine_extension']


[file(vmextensions.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vmextensions.rego
