



# Title: Ensure SQS data is encrypted in Transit using SSL/TLS.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-SQS-008

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sqs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-SQS-008|
|eval|data.rule.sqs_encrypted_in_transit|
|message|data.rule.sqs_encrypted_in_transit_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_SQS_008.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It checks if data in transit is encrypted for SQS service.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA CCM', 'HITRUST', 'ISO/IEC 27002', 'ISO/IEC 27017', 'ISO/IEC 27018', 'MAS TRM', 'NIST CSF', 'NIST SP', 'PCI-DSS', 'RMiT']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_sqs_queue_policy']


[sqs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/sqs.rego
