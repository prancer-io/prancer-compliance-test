



# Master Test ID: PR-AWS-CLD-EKS-011


Master Snapshot Id: ['TEST_EKS', 'TEST_EC2_04']

type: rego

rule: [file(eks.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-EKS-011|
|eval: |data.rule.eks_not_default_vpc|
|message: |data.rule.eks_not_default_vpc_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html#EKS.Client.describe_cluster' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_EKS_011.py|


severity: Medium

title: Ensure EKS cluster is not using the default VPC.

description: It identifies AWS EKS clusters which are configured with the default VPC. It is recommended to use a VPC configuration based on your security and networking requirements. You should create your own EKS VPC instead of using the default, so that you can have full control over the cluster network.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'LGPD', 'CSA CCM', 'CIS', 'CMMC', "CyberSecurity Law of the People's Republic of China", 'HITRUST', 'ISO/IEC 27002', 'ISO/IEC 27017', 'ISO/IEC 27018', 'MAS TRM', 'MLPS', 'NIST 800', 'NIST CSF', 'NIST SP', 'PCI DSS', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CIS AWS 3 Tier Web Architecture Benchmark v.1.0.0-6.31', 'CSA CCM v.4.0.1-DSP-07', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-DSP-17', 'CSA CCM v.4.0.1-IVS-03', 'CSA CCM v.4.0.1-UEM-11', "CyberSecurity Law of the People's Republic of China-Article 21", "CyberSecurity Law of the People's Republic of China-Article 25", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.183', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SI.2.216', 'HITRUST v.9.4.2-Control Reference:01.d', 'HITRUST v.9.4.2-Control Reference:01.r', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.3.1', 'ISO/IEC 27002:2013-13.1.1', 'ISO/IEC 27002:2013-13.1.2', 'ISO/IEC 27002:2013-13.1.3', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.2.5', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-18.1.4', 'ISO/IEC 27002:2013-8.3.1', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017:2015-6.1.1', 'ISO/IEC 27018:2019-10.1.2', 'ISO/IEC 27018:2019-12.3.1', 'MAS TRM 2021-7.2.1', 'MAS TRM 2021-7.2.2', 'MLPS 2.0-8.1.3.2', 'NIST 800-53 Rev 5-Boundary Protection \| Connections to Public Networks', 'NIST 800-53 Rev4-CA-3 (4)', 'NIST CSF-PR.AC-5', 'NIST CSF-PR.DS-5', 'NIST CSF-PR.PT-4', 'NIST SP 800-171 Revision 2-3.13.5', 'NIST SP 800-172-3.13.4e', 'PCI DSS v3.2.1-2.1']|
|service: |['eks', 'ec2']|



[file(eks.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/eks.rego
