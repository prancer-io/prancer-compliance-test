



# Master Test ID: PR-AWS-CLD-RSH-006


Master Snapshot Id: ['TEST_REDSHIFT_1']

type: rego

rule: [file(redshift.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-RSH-006|
|eval: |data.rule.redshift_deploy_vpc|
|message: |data.rule.redshift_deploy_vpc_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html#cfn-redshift-cluster-clustersubnetgroupname' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_RSH_006.py|


severity: Medium

title: Ensure Redshift is not deployed outside of a VPC

description: Ensure that your Redshift clusters are provisioned within the AWS EC2-VPC platform instead of EC2-Classic platform (outdated) for better flexibility and control over clusters security, traffic routing, availability and more.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['PCI DSS', 'HIPAA', 'NIST 800']|
|service: |['redshift']|



[file(redshift.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/redshift.rego
