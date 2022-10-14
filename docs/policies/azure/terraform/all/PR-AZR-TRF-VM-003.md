



# Title: Azure Virtual Machine should have endpoint protection installed


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-VM-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vmextensions.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-VM-003|
|eval|data.rule.vm_protection|
|message|data.rule.vm_protection_err|
|remediationDescription|In 'azurerm_virtual_machine_extension' resource, set type = 'iaasantimalware' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine_extension#type' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_VM_003.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy identifies Azure Virtual Machines (VMs) that do not have endpoint protection installed. Installing endpoint protection systems (like Antimalware for Azure) provides for real-time protection capability that helps identify and remove viruses, spyware, and other malicious software. As a best practice, install endpoint protection on all VMs and computers to help identify and remove viruses, spyware, and other malicious software.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_virtual_machine_extension']


[vmextensions.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vmextensions.rego
