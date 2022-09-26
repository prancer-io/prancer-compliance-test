



# Title: AWS RDS instance is not encrypted


***<font color="white">Master Test Id:</font>*** TEST_RDS_2

***<font color="white">Master Snapshot Id:</font>*** ['ACK_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([rds.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-0125-ACK|
|eval|data.rule.rds_encrypt|
|message|data.rule.rds_encrypt_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies AWS RDS instances which are not encrypted. Amazon Relational Database Service (Amazon RDS) is a web service that makes it easier to set up and manage databases. Amazon allows customers to turn on encryption for RDS which is recommended for compliance and security reasons.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['ack']|



[rds.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/ack/rds.rego
