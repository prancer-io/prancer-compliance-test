



# Title: Azure Virtual Machine should be assigned to an availability set


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-VM-001

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vm.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-VM-001|
|eval|data.rule.vm_aset|
|message|data.rule.vm_aset_err|
|remediationDescription|Make sure you are following the ARM template guidelines for storage accounts by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines' target='_blank'>here</a>|
|remediationFunction|PR_AZR_ARM_VM_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.compute/virtualmachines']


[vm.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego
