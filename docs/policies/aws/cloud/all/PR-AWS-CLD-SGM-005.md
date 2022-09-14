



# Master Test ID: PR-AWS-CLD-SGM-005


Master Snapshot Id: ['TEST_SAGEMAKER', 'TEST_KMS']

type: rego

rule: [file(sagemaker.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-SGM-005|
|eval: |data.rule.sagemaker_customer_managed_key|
|message: |data.rule.sagemaker_customer_managed_key_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sagemaker.html#SageMaker.Client.describe_notebook_instance' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_SGM_005.py|


severity: Medium

title: Ensure AWS SageMaker notebook instance is encrypted using Customer Managed Key.

description: It identifies SageMaker notebook instances that are not encrypted using Customer Managed Key. SageMaker notebook instances should be encrypted with Amazon KMS Customer Master Keys (CMKs) instead of AWS managed-keys in order to have more granular control over the data-at-rest encryption/decryption process and meet compliance requirements. For more details: https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest.html  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'LGPD', 'CSA CCM', 'CMMC', 'HITRUST', 'ISO/IEC 27002', 'ISO/IEC 27017', 'ISO/IEC 27018', 'MAS TRM', 'NIST CSF', 'NIST SP', 'PCI DSS', 'RMiT', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 46', 'Brazilian Data Protection Law (LGPD)-Article 6', 'CSA CCM v.4.0.1-CEK-03', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-UEM-11', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.2.007', 'HITRUST v.9.4.2-Control Reference:06.d', 'HITRUST v.9.4.2-Control Reference:09.s', 'ISO/IEC 27002:2013-10.1.1', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.3.1', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.1.3', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-8.3.1', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017:2015-10.1.1', 'ISO/IEC 27017:2015-10.1.2', 'ISO/IEC 27017:2015-6.1.1', 'ISO/IEC 27018:2019-10.1.2', 'ISO/IEC 27018:2019-12.3.1', 'MAS TRM 2021-11.1.1', 'MAS TRM 2021-11.1.3', 'NIST CSF-PR.DS-1', 'NIST CSF-PR.DS-5', 'NIST SP 800-171 Revision 2-3.13.16', 'NIST SP 800-172-3.1.3e', 'PCI DSS v3.2.1-3.4.1', 'PCI DSS v3.2.1-4.1', 'Risk Management in Technology (RMiT)-10.51', 'Risk Management in Technology (RMiT)-10.68']|
|service: |['sagemaker', 'kms']|



[file(sagemaker.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/sagemaker.rego
