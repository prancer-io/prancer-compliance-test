



# Title: Ensure Redshift database clusters are not using default master username.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-RSH-011

***<font color="white">Master Snapshot Id:</font>*** ['TEST_REDSHIFT_1']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([redshift.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-RSH-011|
|eval|data.rule.redshift_not_default_master_username|
|message|data.rule.redshift_not_default_master_username_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/redshift.html#Redshift.Client.describe_clusters' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_RSH_011.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It is to check that Redshift clusters are not using default master username in order to reduce security risk.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'HIPAA', 'NIST 800']|
|service|['redshift']|



[redshift.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/redshift.rego
