



# Master Test ID: PR-AWS-CLD-WS-003


Master Snapshot Id: ['TEST_ALL_18']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-WS-003|
|eval: |data.rule.workspace_directory_type|
|message: |data.rule.workspace_directory_type_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/workspaces.html#WorkSpaces.Client.describe_workspace_directories' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_WS_003.py|


severity: Medium

title: Ensure AWS WorkSpaces do not use directory type Simple AD.

description: It checks if Simple AD is used for workspace users. MS Active Directory is approved by GS to be used.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['PCI DSS', 'HIPAA', 'GDPR', 'NIST 800']|
|service: |['workspace']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
