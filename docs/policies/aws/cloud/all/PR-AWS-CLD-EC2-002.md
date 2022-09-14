



# Master Test ID: PR-AWS-CLD-EC2-002


Master Snapshot Id: ['TEST_EC2_01']

type: rego

rule: [file(ec2.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-EC2-002|
|eval: |data.rule.ec2_no_vpc|
|message: |data.rule.ec2_no_vpc_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_EC2_002.py|


severity: High

title: AWS EC2 instance is not configured with VPC

description: This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CMMC', 'CSA CCM', 'CSA CCM v.4.0.1-DSP-07', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-DSP-17', 'CSA CCM v.4.0.1-IVS-03', 'CSA CCM v.4.0.1-UEM-11', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 21", "CyberSecurity Law of the People's Republic of China-Article 25", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.183', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SI.2.216', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:09.m', 'ISO/IEC 27002', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.3.1', 'ISO/IEC 27002:2013-13.1.1', 'ISO/IEC 27002:2013-13.1.2', 'ISO/IEC 27002:2013-13.1.3', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.2.5', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-18.1.4', 'ISO/IEC 27002:2013-8.3.1', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017', 'ISO/IEC 27017:2015-6.1.1', 'ISO/IEC 27018', 'ISO/IEC 27018:2019-10.1.2', 'ISO/IEC 27018:2019-12.3.1', 'LGPD', 'MAS TRM', 'MAS TRM 2021-7.2.1', 'MAS TRM 2021-7.2.2', 'MLPS', 'MLPS 2.0-8.1.3.2', 'NIST 800', 'NIST 800-53 Rev 5-Boundary Protection \| Connections to Public Networks', 'NIST 800-53 Rev4-CA-3 (4)', 'NIST CSF', 'NIST CSF-PR.AC-5', 'NIST CSF-PR.DS-5', 'NIST CSF-PR.PT-4', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.5', 'NIST SP 800-172-3.13.4e', 'PCI DSS v3.2.1-1.3.6', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.7.3']|
|service: |['ec2']|



[file(ec2.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ec2.rego
