



# Title: Ensure public access is disabled for AWS MSK.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-MSK-007

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([msk.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-MSK-007|
|eval|data.rule.msk_public_access|
|message|data.rule.msk_public_access_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#aws-resource-msk-cluster--examples' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_MSK_007.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It check whether public access is turned on to the brokers of MSK clusters.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::msk::cluster']


[msk.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/msk.rego
