



# Title: Ensure AWS IAM policy is not overly permissive to STS services.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-IAM-044

***<font color="white">Master Snapshot Id:</font>*** ['TEST_IAM_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-IAM-044|
|eval|data.rule.iam_policy_not_overly_permissive_to_sts_service|
|message|data.rule.iam_policy_not_overly_permissive_to_sts_service_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_policy_versions' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_IAM_044.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It identifies the IAM policies that are overly permissive to STS services. AWS Security Token Service (AWS STS) is a web service that enables you to request temporary credentials for AWS Identity and Access Management (IAM) users or for users that you authenticate (federated users). It is recommended to follow the principle of least privileges ensuring that only restricted STS services for restricted resources.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['AWS Well-Architected Framework', 'AWS Well-Architected Framework-Identity and Access Management', 'MAS TRM', 'MAS TRM 2021-9.1.1', 'RMiT', 'Risk Management in Technology (RMiT)-10.55']|
|service|['iam']|



[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/iam.rego
