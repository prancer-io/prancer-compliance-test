



# Master Test ID: PR-AZR-TRF-NSG-013


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(nsg.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-NSG-013|
|eval: |data.rule.inbound_port_dbs|
|message: |data.rule.inbound_port_dbs_err|
|remediationDescription: ||
|remediationFunction: |PR_AZR_TRF_NSG_013.py|


severity: High

title: Publicly exposed DB Ports

description: DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service: |['terraform']|


resourceTypes: ['azurerm_network_security_rule']


[file(nsg.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/nsg.rego
