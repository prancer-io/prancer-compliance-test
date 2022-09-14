



# Master Test ID: PR-AWS-CLD-EC2-011


Master Snapshot Id: ['TEST_EC2_01']

type: rego

rule: [file(ec2.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-EC2-011|
|eval: |data.rule.ebs_volume_attached|
|message: |data.rule.ebs_volume_attached_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-volumes.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_EC2_011.py|


severity: Low

title: Ensure EBS volume is attached

description: This control check if EBS snapshots are encrypted at-rest. Snapshots of EBS volumes should be encrypted to avoid misuse. Encryption can be enabled at the account level for EBS volumes and snapshots  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['ec2']|



[file(ec2.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ec2.rego
