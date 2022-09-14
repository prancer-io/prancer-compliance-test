



# Master Test ID: PR-AZR-TRF-NSG-011


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(nsg.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-NSG-011|
|eval: |data.rule.inbound_port_11211|
|message: |data.rule.inbound_port_11211_err|
|remediationDescription: ||
|remediationFunction: |PR_AZR_TRF_NSG_011.py|


severity: High

title: Memcached DDoS attack attempt should be prevented

description: Memcached is a general-purpose distributed memory caching system. It is often used to speed up dynamic database-driven websites by caching data and objects in RAM to reduce the number of times an external data source (such as a database or API) must be read. It is reported that Memcache versions 1.5.5 and below are vulnerable to DDoS amplification attack. This policy aims at finding such attacks and generate alerts.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service: |['terraform']|


resourceTypes: ['azurerm_network_security_rule']


[file(nsg.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/nsg.rego
