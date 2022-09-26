



# Title: Ensure Redshift database clusters are not using default master username.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-RSH-011

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([redshift.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-RSH-011|
|eval|data.rule.redshift_not_default_master_username|
|message|data.rule.redshift_not_default_master_username_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_RSH_011.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It is to check that Redshift clusters are not using default master username in order to reduce security risk.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI DSS', 'HIPAA', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::redshift::cluster']


[redshift.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/redshift.rego
