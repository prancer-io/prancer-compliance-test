



# Title: Ensure Lambda IAM policy is not overly permissive to all traffic


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-IAM-011

***<font color="white">Master Snapshot Id:</font>*** ['TEST_IAM_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-IAM-011|
|eval|data.rule.lambda_iam_policy_not_overly_permissive_to_all_traffic|
|message|data.rule.lambda_iam_policy_not_overly_permissive_to_all_traffic_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_policy_versions' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_IAM_011.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure that the Lambda should be granted access restrictions so that only authorized users and applications have access to the service. For more details: https://docs.aws.amazon.com/lambda/latest/dg/security-iam.html  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'AWS Well-Architected Framework-Identity and Access Management', 'LGPD', 'CSA CCM', "CyberSecurity Law of the People's Republic of China", 'CMMC', 'GDPR', 'HITRUST', 'MAS TRM', 'MITRE ATT&CK', 'MLPS', 'NIST 800', 'NIST CSF', 'RMiT', 'SOC 2']|
|service|['iam']|



[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/iam.rego
