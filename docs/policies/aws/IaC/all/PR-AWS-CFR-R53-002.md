



# Title: Ensure that the Route53 RecordSet Type is A or CNAME.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-R53-002

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-R53-002|
|eval|data.rule.route_recordset_approved_type|
|message|data.rule.route_recordset_approved_type_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_R53_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure that the Route53 RecordSet Type is A or CNAME.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::route53::recordset']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/all.rego
