



# Master Test ID: PR-AWS-CLD-RSH-010


***<font color="white">Master Snapshot Id:</font>*** ['TEST_REDSHIFT_1']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([redshift.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-RSH-010|
|eval|data.rule.redshift_deferred_maintenance_window|
|message|data.rule.redshift_deferred_maintenance_window_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/redshift.html#Redshift.Client.describe_clusters' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_RSH_010.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** Ensure deferred maintenance window is enabled for Redshift cluster.

***<font color="white">Description:</font>*** It is to check that deferred maintenance window is enabled in order to keep Redshift cluster running without interruption during critical business periods.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'HIPAA', 'NIST 800']|
|service|['redshift']|



[redshift.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/redshift.rego
