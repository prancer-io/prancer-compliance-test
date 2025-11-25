package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-clusterparametergroup.html

available_false_choices := ["false", false]
available_true_choices := ["true", true]

#
# PR-AWS-CLD-RSH-001
#

default redshift_encrypt_key = true

redshift_encrypt_key = false {
    REDSHIFT := input.TEST_REDSHIFT_1[_]
    Cluster := REDSHIFT.Clusters[_]
    not Cluster.KmsKeyId
}

redshift_encrypt_key = false {
    REDSHIFT := input.TEST_REDSHIFT_1[_]
    Cluster := REDSHIFT.Clusters[_]

    KMS := input.TEST_KMS[_]
    Cluster.KmsKeyId == KMS.KeyMetadata.Arn
    alias := KMS.Aliases[_]
    alias.AliasName == "alias/aws/redshift"
}

redshift_encrypt_key = false {
    REDSHIFT := input.TEST_REDSHIFT_1[_]
    Cluster := REDSHIFT.Clusters[_]
    not Cluster.Encrypted
}

redshift_encrypt_key_err = "AWS Redshift Cluster not encrypted using Customer Managed Key" {
    not redshift_encrypt_key
}

redshift_encrypt_key_metadata := {
    "Policy Code": "PR-AWS-CLD-RSH-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Redshift Cluster not encrypted using Customer Managed Key",
    "Policy Description": "This policy identifies Redshift Clusters which are encrypted with default KMS keys and not with Keys managed by Customer. It is a best practice to use customer managed KMS Keys to encrypt your Redshift databases data. Customer-managed CMKs give you more flexibility, including the ability to create, rotate, disable, define access control for, and audit the encryption keys used to help protect your data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}

#
# PR-AWS-CLD-RSH-002
#

default redshift_public = true

redshift_public = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    Clusters.PubliclyAccessible == true
}

redshift_public_err = "AWS Redshift clusters should not be publicly accessible" {
    not redshift_public
}

redshift_public_metadata := {
    "Policy Code": "PR-AWS-CLD-RSH-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Redshift clusters should not be publicly accessible",
    "Policy Description": "This policy identifies AWS Redshift clusters which are accessible publicly.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}

#
# PR-AWS-CLD-RSH-003
#

default redshift_require_ssl = true

redshift_require_ssl = false {
    # lower(resource.Type) == "aws::redshift::clusterparametergroup"
    not input.Parameters
}

redshift_require_ssl = false {
    # lower(resource.Type) == "aws::redshift::clusterparametergroup"
    count([c | lower(input.Parameters[_].ParameterName) == "require_ssl"; c := 1]) == 0
}

redshift_require_ssl = false {
    # lower(resource.Type) == "aws::redshift::clusterparametergroup"
    params = input.Parameters[j]
    lower(params.ParameterName) == "require_ssl"
    lower(params.ParameterValue) == "false"
}

redshift_require_ssl_err = "AWS Redshift does not have require_ssl configured" {
    not redshift_require_ssl
}

redshift_require_ssl_metadata := {
    "Policy Code": "PR-AWS-CLD-RSH-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Redshift does not have require_ssl configured",
    "Policy Description": "This policy identifies Redshift databases in which data connection to and from is occurring on an insecure channel. SSL connections ensures the security of the data in transit.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}

#
# PR-AWS-CLD-RSH-004
#

default redshift_encrypt = true

redshift_encrypt = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    not Clusters.Encrypted
}

redshift_encrypt_err = "AWS Redshift instances are not encrypted" {
    not redshift_encrypt
}

redshift_encrypt_metadata := {
    "Policy Code": "PR-AWS-CLD-RSH-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Redshift instances are not encrypted",
    "Policy Description": "This policy identifies AWS Redshift instances which are not encrypted. These instances should be encrypted for clusters to help protect data at rest which otherwise can result in a data breach.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}


#
# PR-AWS-CLD-RSH-005
#

default redshift_allow_version_upgrade = true

redshift_allow_version_upgrade = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    not Clusters.AllowVersionUpgrade
}

redshift_allow_version_upgrade_err = "Ensure Redshift cluster allow version upgrade by default" {
    not redshift_allow_version_upgrade
}

redshift_allow_version_upgrade_metadata := {
    "Policy Code": "PR-AWS-CLD-RSH-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Redshift cluster allow version upgrade by default",
    "Policy Description": "This policy identifies AWS Redshift instances which has not enabled AllowVersionUpgrade. major version upgrades can be applied during the maintenance window to the Amazon Redshift engine that is running on the cluster. When a new major version of the Amazon Redshift engine is released, you can request that the service automatically apply upgrades during the maintenance window to the Amazon Redshift engine that is running on your cluster.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html#cfn-redshift-cluster-allowversionupgrade"
}


#
# PR-AWS-CLD-RSH-006
#

default redshift_deploy_vpc = true

redshift_allow_version_upgrade = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    count(Clusters.ClusterSubnetGroupName) == 0
}

redshift_allow_version_upgrade = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    Clusters.ClusterSubnetGroupName == null
}

redshift_allow_version_upgrade = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    not Clusters.ClusterSubnetGroupName
}

redshift_deploy_vpc_err = "Ensure Redshift is not deployed outside of a VPC" {
    not redshift_allow_version_upgrade
}

redshift_deploy_vpc_metadata := {
    "Policy Code": "PR-AWS-CLD-RSH-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Redshift is not deployed outside of a VPC",
    "Policy Description": "Ensure that your Redshift clusters are provisioned within the AWS EC2-VPC platform instead of EC2-Classic platform (outdated) for better flexibility and control over clusters security, traffic routing, availability and more.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html#cfn-redshift-cluster-clustersubnetgroupname"
}


#
# PR-AWS-CLD-RSH-007
#

default redshift_audit = true

redshift_audit = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    not Clusters.LoggingProperties.BucketName
}

redshift_audit = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    count(Clusters.LoggingProperties.BucketName) == 0
}

redshift_audit_err = "AWS Redshift database does not have audit logging enabled" {
    not redshift_audit
}

redshift_audit_metadata := {
    "Policy Code": "PR-AWS-CLD-RSH-007",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Redshift database does not have audit logging enabled",
    "Policy Description": "Audit logging is not enabled by default in Amazon Redshift. When you enable logging on your cluster, Amazon Redshift creates and uploads logs to Amazon S3 that capture data from the creation of the cluster to the present time.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}


#
# PR-AWS-CLD-RSH-008
# aws::redshift::cluster

default redshift_enhanced_vpc_routing = true

redshift_enhanced_vpc_routing = false {
    Clusters := input.Clusters[_]
    Clusters.EnhancedVpcRouting == available_false_choices[_]
}

redshift_enhanced_vpc_routing_err = "Ensure AWS Redshift - Enhanced VPC routing must be enabled." {
    not redshift_enhanced_vpc_routing
}

redshift_enhanced_vpc_routing_metadata := {
    "Policy Code": "PR-AWS-CLD-RSH-008",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS Redshift - Enhanced VPC routing must be enabled.",
    "Policy Description": "It is to check enhanced VPC routing is enabled or not forces all COPY and UNLOAD traffic between your cluster and your data repositories through your virtual private cloud (VPC) based on the Amazon VPC service.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/redshift.html#Redshift.Client.describe_clusters"
}


#
# PR-AWS-CLD-RSH-009
# aws::redshift::cluster

default redshift_not_provisioned_with_ec2_classic = true

redshift_not_provisioned_with_ec2_classic = false {
    Clusters := input.Clusters[_]
    not Clusters.VpcId
}

redshift_not_provisioned_with_ec2_classic = false {
    Clusters := input.Clusters[_]
    Clusters.VpcId == ""
}

redshift_not_provisioned_with_ec2_classic = false {
    Clusters := input.Clusters[_]
    Clusters.VpcId == null
}

redshift_not_provisioned_with_ec2_classic_err = "Ensure Redshift cluster is not provisioned using EC2-classic (deprecated) platform." {
    not redshift_not_provisioned_with_ec2_classic
}

redshift_not_provisioned_with_ec2_classic_metadata := {
    "Policy Code": "PR-AWS-CLD-RSH-009",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Redshift cluster is not provisioned using EC2-classic (deprecated) platform.",
    "Policy Description": "It is to check that the Redshift cluster is not provisioned using the deprecated EC2-classic instance to reduce the risk level associated with deprecated resources.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/redshift.html#Redshift.Client.describe_clusters"
}


#
# PR-AWS-CLD-RSH-010
# aws::redshift::cluster

default redshift_deferred_maintenance_window = true

redshift_deferred_maintenance_window = false {
    Clusters := input.Clusters[_]
    Clusters.DeferredMaintenanceWindows == null
}

redshift_deferred_maintenance_window = false {
    Clusters := input.Clusters[_]
    Clusters.DeferredMaintenanceWindows == ""
}

redshift_deferred_maintenance_window = false {
    Clusters := input.Clusters[_]
    not Clusters.DeferredMaintenanceWindows
}

redshift_deferred_maintenance_window = false {
    Clusters := input.Clusters[_]
    count(Clusters.DeferredMaintenanceWindows) == 0
}

redshift_deferred_maintenance_window_err = "Ensure deferred maintenance window is enabled for Redshift cluster." {
    not redshift_deferred_maintenance_window
}

redshift_deferred_maintenance_window_metadata := {
    "Policy Code": "PR-AWS-CLD-RSH-010",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure deferred maintenance window is enabled for Redshift cluster.",
    "Policy Description": "It is to check that deferred maintenance window is enabled in order to keep Redshift cluster running without interruption during critical business periods.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/redshift.html#Redshift.Client.describe_clusters"
}


#
# PR-AWS-CLD-RSH-011
# aws::redshift::cluster

default redshift_not_default_master_username = true

redshift_not_default_master_username = false {
    Clusters := input.Clusters[_]
    lower(Clusters.MasterUsername) == "awsuser"
}

redshift_not_default_master_username_err = "Ensure Redshift database clusters are not using default master username." {
    not redshift_not_default_master_username
}

redshift_not_default_master_username_metadata := {
    "Policy Code": "PR-AWS-CLD-RSH-011",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Redshift database clusters are not using default master username.",
    "Policy Description": "It is to check that Redshift clusters are not using default master username in order to reduce security risk.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/redshift.html#Redshift.Client.describe_clusters"
}


#
# PR-AWS-CLD-RSH-012
# aws::redshift::cluster

default redshift_not_default_port = true

redshift_not_default_port = false {
    Clusters := input.Clusters[_]
    Clusters.Endpoint.Port == 5439
}

redshift_not_default_port_err = "Ensure Redshift database clusters are not using default port(5439) for database connection." {
    not redshift_not_default_port
}

redshift_not_default_port_metadata := {
    "Policy Code": "PR-AWS-CLD-RSH-012",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Redshift database clusters are not using default port(5439) for database connection.",
    "Policy Description": "It is to check that Redshift cluster is not configured using default port to reduce security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/redshift.html#Redshift.Client.describe_clusters"
}


#
# PR-AWS-CLD-RSH-013
# aws::redshift::cluster

default redshift_automated_backup = true

redshift_automated_backup = false {
    Clusters := input.Clusters[_]
    Clusters.AutomatedSnapshotRetentionPeriod == 0
}

redshift_automated_backup_err = "Ensure automated backups are enabled for Redshift cluster." {
    not redshift_automated_backup
}

redshift_automated_backup_metadata := {
    "Policy Code": "PR-AWS-CLD-RSH-013",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure automated backups are enabled for Redshift cluster.",
    "Policy Description": "It is to check automated backup is turned on in order to recover data in the event of failures.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/redshift.html#Redshift.Client.describe_clusters"
}