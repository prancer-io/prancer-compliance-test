



# Title: Ensure every Security Group rule contains a description


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-SG-023

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([securitygroup.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-SG-023|
|eval|data.rule.sg_description_absent|
|message|data.rule.sg_description_absent_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group-rule-1.html#cfn-ec2-security-group-rule-description' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_SG_023.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ec2::securitygroup']


[securitygroup.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego
