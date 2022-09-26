



# Title: Ensure IAM groups contains at least one IAM user


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-IAM-008

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-IAM-008|
|eval|data.rule.iam_user_group_attach|
|message|data.rule.iam_user_group_attach_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-addusertogroup.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_IAM_008.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Ensure that your Amazon Identity and Access Management (IAM) users are members of at least one IAM group in order to adhere to IAM security best practices  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::iam::usertogroupaddition']


[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego
