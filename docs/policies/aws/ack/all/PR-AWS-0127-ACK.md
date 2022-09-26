



# Title: AWS RDS instance with Multi-Availability Zone disabled


***<font color="white">Master Test Id:</font>*** TEST_RDS_3

***<font color="white">Master Snapshot Id:</font>*** ['ACK_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([rds.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-0127-ACK|
|eval|data.rule.rds_multiaz|
|message|data.rule.rds_multiaz_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies RDS instances which have Multi-Availability Zone(Multi-AZ) disabled. When RDS DB instance is enabled with Multi-AZ, RDS automatically creates a primary DB Instance and synchronously replicates the data to a standby instance in a different availability zone. These Multi-AZ deployments will improve primary node reachability by providing read replica in case of network connectivity loss or loss of availability in the primaryâ€™s availability zone for read/write operations, so by making them the best fit for production database workloads.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['ack']|



[rds.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/ack/rds.rego
