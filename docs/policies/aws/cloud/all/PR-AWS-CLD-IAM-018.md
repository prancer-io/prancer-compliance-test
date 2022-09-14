



# Master Test ID: PR-AWS-CLD-IAM-018


Master Snapshot Id: ['TEST_IAM_02']

type: rego

rule: [file(iam.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-IAM-018|
|eval: |data.rule.elasticbeanstalk_platform_with_iam_wildcard_resource_access|
|message: |data.rule.elasticbeanstalk_platform_with_iam_wildcard_resource_access_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_IAM_018.py|


severity: Low

title: Ensure that the AWS policies don't have '*' in the resource section of the policy statement of elastic bean stalk.

description: It identifies AWS IAM permissions that contain '*' in the resource section of the policy statement of elastic bean stalk. The policy will identify those '*' only in case using '*' is not mandatory.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'AWS Well-Architected Framework-Identity and Access Management', 'LGPD', 'CSA CCM', "CyberSecurity Law of the People's Republic of China", 'CMMC', 'GDPR', 'HITRUST', 'MAS TRM', 'MITRE ATT&CK', 'MLPS', 'NIST 800', 'NIST CSF', 'RMiT', 'SOC 2']|
|service: |['iam']|



[file(iam.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/iam.rego
