



# Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-VM-002

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vm.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-VM-002|
|eval|data.rule.linux_configuration|
|message|data.rule.linux_configuration_err|
|remediationDescription|For Resource type 'microsoft.compute/virtualmachines' make sure osProfile.linuxConfiguration.disablePasswordAuthentication exists and the value is set to true.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_VM_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** SSH is an encrypted connection protocol that allows secure sign-ins over unsecured connections. SSH is the default connection protocol for Linux VMs hosted in Azure. Using secure shell (SSH) key pair, it is possible to spin up a Linux virtual machine on Azure that defaults to using SSH keys for authentication, eliminating the need for passwords to sign in. We recommend connecting to a VM using SSH keys. Using basic authentication with SSH connections leaves VMs vulnerable to brute-force attacks or guessing of passwords.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.compute/virtualmachines']


[vm.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego
