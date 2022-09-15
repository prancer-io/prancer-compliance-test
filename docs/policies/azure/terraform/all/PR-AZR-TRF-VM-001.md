



# Master Test ID: PR-AZR-TRF-VM-001


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vm.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-VM-001|
|eval|data.rule.vm_aset|
|message|data.rule.vm_aset_err|
|remediationDescription|In 'azurerm_virtual_machine' resource, make sure 'availability_set_id' property exist and its value is set from id of 'azurerm_availability_set' resource to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#availability_set_id' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_VM_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Azure Virtual Machine should be assigned to an availability set

***<font color="white">Description:</font>*** To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_virtual_machine', 'azurerm_windows_virtual_machine', 'azurerm_linux_virtual_machine_scale_set', 'azurerm_linux_virtual_machine']


[vm.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego
