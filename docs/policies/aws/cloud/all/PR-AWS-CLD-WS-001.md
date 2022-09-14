



# Master Test ID: PR-AWS-CLD-WS-001


Master Snapshot Id: ['TEST_ALL_04']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-WS-001|
|eval: |data.rule.workspace_volume_encrypt|
|message: |data.rule.workspace_volume_encrypt_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-workspaces-workspace.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_WS_001.py|


severity: Medium

title: Ensure that Workspace user volumes is encrypted

description: Ensure that your Amazon WorkSpaces storage volumes are encrypted in order to meet security and compliance requirements. Your data is transparently encrypted while being written and transparently decrypted while being read from your storage volumes, therefore the encryption process does not require any additional action from you  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['PCI DSS', 'HIPAA', 'GDPR', 'NIST 800']|
|service: |['workspace']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
