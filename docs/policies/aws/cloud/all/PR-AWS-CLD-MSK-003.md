



# Master Test ID: PR-AWS-CLD-MSK-003


Master Snapshot Id: ['TEST_MSK']

type: rego

rule: [file(msk.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-MSK-003|
|eval: |data.rule.msk_in_transit_encryption_tls|
|message: |data.rule.msk_in_transit_encryption_tls_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_MSK_003.py|


severity: High

title: Ensure client authentication is enabled with TLS (mutual TLS authentication)

description: Enable TLS by setting EncryptionInfo.EncryptionInTransit.ClientBroker value to 'TLS'. to provide trasport layes security to MSK instance  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['GDPR', 'NIST 800']|
|service: |['msk']|



[file(msk.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/msk.rego
