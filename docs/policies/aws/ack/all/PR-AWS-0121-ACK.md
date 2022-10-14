



# Title: AWS RDS database instance is publicly accessible


***<font color="white">Master Test Id:</font>*** TEST_RDS_1

***<font color="white">Master Snapshot Id:</font>*** ['ACK_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([rds.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-0121-ACK|
|eval|data.rule.rds_public|
|message|data.rule.rds_public_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies RDS database instances which are publicly accessible.DB instances should not be publicly accessible to protect the integrety of data.Public accessibility of DB instances can be modified by turning on or off the Public accessibility parameter.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['ack']|



[rds.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/ack/rds.rego
