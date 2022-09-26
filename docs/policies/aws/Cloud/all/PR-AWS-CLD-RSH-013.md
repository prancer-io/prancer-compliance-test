



# Title: Ensure automated backups are enabled for Redshift cluster.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-RSH-013

***<font color="white">Master Snapshot Id:</font>*** ['TEST_REDSHIFT_1']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([redshift.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-RSH-013|
|eval|data.rule.redshift_automated_backup|
|message|data.rule.redshift_automated_backup_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/redshift.html#Redshift.Client.describe_clusters' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_RSH_013.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It is to check automated backup is turned on in order to recover data in the event of failures.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'HIPAA', 'NIST 800']|
|service|['redshift']|



[redshift.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/redshift.rego
