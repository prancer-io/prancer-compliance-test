



# Title: AWS RDS minor upgrades not enabled


***<font color="white">Master Test Id:</font>*** TEST_RDS_6

***<font color="white">Master Snapshot Id:</font>*** ['ACK_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([rds.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-0130-ACK|
|eval|data.rule.rds_upgrade|
|message|data.rule.rds_upgrade_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** When Amazon Relational Database Service (Amazon RDS) supports a new version of a database engine, you can upgrade your DB instances to the new version. There are two kinds of upgrades: major version upgrades and minor version upgrades. Minor upgrades helps maintain a secure and stable RDS with minimal impact on the application. For this reason, we recommend that your automatic minor upgrade is enabled. Minor version upgrades only occur automatically if a minor upgrade replaces an unsafe version, such as a minor upgrade that contains bug fixes for a previous version.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['ack']|



[rds.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/ack/rds.rego
