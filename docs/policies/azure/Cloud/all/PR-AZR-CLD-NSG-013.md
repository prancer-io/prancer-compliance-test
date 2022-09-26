



# Title: Publicly should not expose DB Ports


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-NSG-013

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_231']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([nsg.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-NSG-013|
|eval|data.rule.inbound_port_dbs|
|message|data.rule.inbound_port_dbs_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/security/fundamentals/network-overview' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_NSG_013.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['Networking']|



[nsg.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/nsg.rego
