



# Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-VM-002

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_274']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vm.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-VM-002|
|eval|data.rule.linux_configuration|
|message|data.rule.linux_configuration_err|
|remediationDescription|To change the policy using the Azure Portal, follow these steps:<br><br><br>1. Log in to the Azure Portal at https://portal.azure.com.<br>2. Enter virtual machines in the search bar.<br>3. Under Services, select Virtual machines.<br>4. Under Administrator account, select SSH public key.<br>5. For SSH public key source, use the default Generate new key pair, then for Key pair name enter myKey.<br>6. Under Inbound port rules > Public inbound ports, select Allow selected ports, then select SSH (22) and HTTP (80) from the drop-down.<br>7. Leave the remaining defaults settings. At the bottom of the page click Review + create.|
|remediationFunction|PR_AZR_CLD_VM_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** SSH is an encrypted connection protocol that allows secure sign-ins over unsecured connections. SSH is the default connection protocol for Linux VMs hosted in Azure. Using secure shell (SSH) key pair, it is possible to spin up a Linux virtual machine on Azure that defaults to using SSH keys for authentication, eliminating the need for passwords to sign in. We recommend connecting to a VM using SSH keys. Using basic authentication with SSH connections leaves VMs vulnerable to brute-force attacks or guessing of passwords.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|[]|
|service|['Compute']|



[vm.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/vm.rego
