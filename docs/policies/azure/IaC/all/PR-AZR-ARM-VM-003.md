



# Title: Azure Virtual Machine should have endpoint protection installed


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-VM-003

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vmextensions.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-VM-003|
|eval|data.rule.vm_protection|
|message|data.rule.vm_protection_err|
|remediationDescription|Make sure you are following the ARM template guidelines for extensions by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines/extensions' target='_blank'>here</a>|
|remediationFunction|PR_AZR_ARM_VM_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Azure Virtual Machines (VMs) that do not have endpoint protection installed. Installing endpoint protection systems (like Antimalware for Azure) provides for real-time protection capability that helps identify and remove viruses, spyware, and other malicious software. As a best practice, install endpoint protection on all VMs and computers to help identify and remove viruses, spyware, and other malicious software.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.compute/virtualmachines/extensions']


[vmextensions.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vmextensions.rego
