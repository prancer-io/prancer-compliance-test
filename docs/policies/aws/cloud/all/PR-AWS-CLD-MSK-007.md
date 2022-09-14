



# Master Test ID: PR-AWS-CLD-MSK-007


Master Snapshot Id: ['TEST_MSK']

type: rego

rule: [file(msk.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-MSK-007|
|eval: |data.rule.msk_public_access|
|message: |data.rule.msk_public_access_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kafka.html#Kafka.Client.describe_cluster' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_MSK_007.py|


severity: High

title: Ensure public access is disabled for AWS MSK.

description: It check whether public access is turned on to the brokers of MSK clusters.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['GDPR', 'NIST 800']|
|service: |['msk']|



[file(msk.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/msk.rego
