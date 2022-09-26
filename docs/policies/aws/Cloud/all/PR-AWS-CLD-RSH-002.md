



# Title: AWS Redshift clusters should not be publicly accessible


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-RSH-002

***<font color="white">Master Snapshot Id:</font>*** ['TEST_REDSHIFT_1']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([redshift.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-RSH-002|
|eval|data.rule.redshift_public|
|message|data.rule.redshift_public_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_RSH_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy identifies AWS Redshift clusters which are accessible publicly.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['CSA CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'SOC 2']|
|service|['redshift']|



[redshift.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/redshift.rego
