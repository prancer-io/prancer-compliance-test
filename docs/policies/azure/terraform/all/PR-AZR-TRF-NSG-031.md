



# Master Test ID: PR-AZR-TRF-NSG-031


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(nsg.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-NSG-031|
|eval: |data.rule.outbound_port_bitcoin|
|message: |data.rule.outbound_port_bitcoin_err|
|remediationDescription: ||
|remediationFunction: |PR_AZR_TRF_NSG_031.py|


severity: Medium

title: Instance is communicating with ports known to mine Bitcoin

description: Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['HIPAA', 'NIST CSF']|
|service: |['terraform']|


resourceTypes: ['azurerm_network_security_rule']


[file(nsg.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/nsg.rego
