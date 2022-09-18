



# Title: Ensure SQS is only accessible via specific VPCe service.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-SQS-007

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sqs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-SQS-007|
|eval|data.rule.sqs_accessible_via_specific_vpc|
|message|data.rule.sqs_accessible_via_specific_vpc_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_SQS_007.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It checks if SQS to other AWS services communication is managed by VPC endpoint and polcicies attached to it  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA CCM', 'HITRUST', 'ISO/IEC 27002', 'ISO/IEC 27017', 'ISO/IEC 27018', 'MAS TRM', 'NIST CSF', 'NIST SP', 'PCI-DSS', 'RMiT']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_sqs_queue_policy']


[sqs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/sqs.rego
