



# Master Test ID: PR-AWS-CLD-MSK-004


Master Snapshot Id: ['TEST_MSK']

type: rego

rule: [file(msk.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-MSK-004|
|eval: |data.rule.msk_vpc|
|message: |data.rule.msk_vpc_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_MSK_004.py|


severity: Medium

title: Ensure MSK cluster is setup in GS VPC

description: To Add MKS Cluster in gs VPC,Specify exactly two subnets if you are using the US West (N. California) Region. For other Regions where Amazon MSK is available, you can specify either two or three subnets. The subnets that you specify must be in distinct Availability Zones. When you create a cluster, Amazon MSK distributes the broker nodes evenly across the subnets that you specify.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['Best Practice']|
|service: |['msk']|



[file(msk.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/msk.rego
