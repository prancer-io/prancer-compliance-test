



# Title: OPEN CASSANDRA PORT


***<font color="white">Master Test Id:</font>*** TEST_ComputeFirewall_3

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ComputeFirewall.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0004-KCC|
|eval|data.rule.open_cassandra_port|
|message|data.rule.open_cassandra_port_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** A firewall is configured to have an open CASSANDRA port that allows generic access.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['computefirewall']


[ComputeFirewall.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego
