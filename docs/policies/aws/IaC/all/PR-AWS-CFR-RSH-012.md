



# Title: Ensure Redshift database clusters are not using default port(5439) for database connection.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-RSH-012

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([redshift.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-RSH-012|
|eval|data.rule.redshift_not_default_port|
|message|data.rule.redshift_not_default_port_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_RSH_012.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It is to check that Redshift cluster is not configured using default port to reduce security risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI DSS', 'HIPAA', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::redshift::cluster']


[redshift.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/redshift.rego
