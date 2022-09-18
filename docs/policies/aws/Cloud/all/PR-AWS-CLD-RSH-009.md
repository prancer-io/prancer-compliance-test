



# Title: Ensure Redshift cluster is not provisioned using EC2-classic (deprecated) platform.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-RSH-009

***<font color="white">Master Snapshot Id:</font>*** ['TEST_REDSHIFT_1']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([redshift.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-RSH-009|
|eval|data.rule.redshift_not_provisioned_with_ec2_classic|
|message|data.rule.redshift_not_provisioned_with_ec2_classic_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/redshift.html#Redshift.Client.describe_clusters' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_RSH_009.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It is to check that the Redshift cluster is not provisioned using the deprecated EC2-classic instance to reduce the risk level associated with deprecated resources.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'HIPAA', 'NIST 800']|
|service|['redshift']|



[redshift.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/redshift.rego
