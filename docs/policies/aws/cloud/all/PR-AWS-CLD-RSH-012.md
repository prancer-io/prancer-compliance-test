



# Master Test ID: PR-AWS-CLD-RSH-012


***<font color="white">Master Snapshot Id:</font>*** ['TEST_REDSHIFT_1']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([redshift.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-RSH-012|
|eval|data.rule.redshift_not_default_port|
|message|data.rule.redshift_not_default_port_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/redshift.html#Redshift.Client.describe_clusters' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_RSH_012.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** Ensure Redshift database clusters are not using default port(5439) for database connection.

***<font color="white">Description:</font>*** It is to check that Redshift cluster is not configured using default port to reduce security risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'HIPAA', 'NIST 800']|
|service|['redshift']|



[redshift.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/redshift.rego
