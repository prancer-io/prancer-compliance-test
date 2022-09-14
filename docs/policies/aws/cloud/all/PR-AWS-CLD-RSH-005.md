



# Master Test ID: PR-AWS-CLD-RSH-005


Master Snapshot Id: ['TEST_REDSHIFT_1']

type: rego

rule: [file(redshift.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-RSH-005|
|eval: |data.rule.redshift_allow_version_upgrade|
|message: |data.rule.redshift_allow_version_upgrade_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html#cfn-redshift-cluster-allowversionupgrade' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_RSH_005.py|


severity: Medium

title: Ensure Redshift cluster allow version upgrade by default

description: This policy identifies AWS Redshift instances which has not enabled AllowVersionUpgrade. major version upgrades can be applied during the maintenance window to the Amazon Redshift engine that is running on the cluster. When a new major version of the Amazon Redshift engine is released, you can request that the service automatically apply upgrades during the maintenance window to the Amazon Redshift engine that is running on your cluster.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['PCI DSS', 'NIST 800']|
|service: |['redshift']|



[file(redshift.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/redshift.rego
