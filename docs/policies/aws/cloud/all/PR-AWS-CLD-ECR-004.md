



# Master Test ID: PR-AWS-CLD-ECR-004


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ECR']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecr.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ECR-004|
|eval|data.rule.ecr_public_access_disable|
|message|data.rule.ecr_public_access_disable_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-repository-imagescanningconfiguration.html#cfn-ecr-repository-imagescanningconfiguration-scanonpush' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ECR_004.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Ensure AWS ECR Repository is not publicly accessible

***<font color="white">Description:</font>*** Public AWS ECR Repository potentially expose existing interfaces to unwanted 3rd parties that can tap into an existing data stream, resulting in data leak to an unwanted party.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'GDPR']|
|service|['ecr']|



[ecr.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecr.rego
