package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html

#
# PR-AWS-0002-CFR
#

default api_gw_cert = null

aws_issue["api_gw_cert"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    not resource.Properties.ClientCertificateId
}

aws_issue["api_gw_cert"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    count(resource.Properties.ClientCertificateId) == 0
}

api_gw_cert {
    lower(input.Resources[i].Type) == "aws::apigateway::stage"
    not aws_issue["api_gw_cert"]
}

api_gw_cert = false {
    aws_issue["api_gw_cert"]
}

api_gw_cert_err = "AWS API Gateway endpoints without client certificate authentication" {
    aws_issue["api_gw_cert"]
}

api_gw_cert_metadata := {
    "Policy Code": "PR-AWS-0002-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS API Gateway endpoints without client certificate authentication",
    "Policy Description": "API Gateway can generate an SSL certificate and use its public key in the backend to verify that HTTP requests to your backend system are from API Gateway. This allows your HTTP backend to control and accept only requests originating from Amazon API Gateway, even if the backend is publicly accessible._x005F_x000D_ _x005F_x000D_ Note: Some backend servers may not support SSL client authentication as API Gateway does and could return an SSL certificate error. For a list of incompatible backend servers, see Known Issues. https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}

#
# gID6
#

default db_exposed = null

db_ports := [
    1433, 1521, 3306, 5000, 5432, 5984, 6379, 6380, 8080, 9042, 11211, 27017, 28015, 29015, 50000
]

aws_issue["db_exposed"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    ingress := resource.Properties.SecurityGroupIngress[_]
    port := db_ports[_]
    ingress.CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

aws_issue["db_exposed"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    ingress := resource.Properties.SecurityGroupIngress[_]
    port := db_ports[_]
    ingress.CidrIpv6="::/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

db_exposed {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["db_exposed"]
}

db_exposed = false {
    aws_issue["db_exposed"]
}

db_exposed_err = "Publicly exposed DB Ports" {
    aws_issue["db_exposed"]
}

db_exposed_metadata := {
    "Policy Code": "",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Publicly exposed DB Ports",
    "Policy Description": "DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}

#
# gID1
#

default bitcoin_ports = null

bc_ports := [
    8332, 8333
]

aws_issue["bitcoin_ports"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    ingress := resource.Properties.SecurityGroupIngress[_]
    port := bc_ports[_]
    ingress.CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

aws_issue["bitcoin_ports"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    ingress := resource.Properties.SecurityGroupIngress[_]
    port := bc_ports[_]
    ingress.CidrIpv6="::/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

bitcoin_ports {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["bitcoin_ports"]
}

bitcoin_ports = false {
    aws_issue["bitcoin_ports"]
}

bitcoin_ports_err = "Instance is communicating with ports known to mine Bitcoin" {
    aws_issue["bitcoin_ports"]
}

bitcoin_ports_metadata := {
    "Policy Code": "",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Instance is communicating with ports known to mine Bitcoin",
    "Policy Description": "Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}

#
# gID2
#

default ethereum_ports = null

eth_ports := [
    8545, 30303
]

aws_issue["ethereum_ports"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    ingress := resource.Properties.SecurityGroupIngress[_]
    port := eth_ports[_]
    ingress.CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

aws_issue["ethereum_ports"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    ingress := resource.Properties.SecurityGroupIngress[_]
    port := eth_ports[_]
    ingress.CidrIpv6="::/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

ethereum_ports {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["ethereum_ports"]
}

ethereum_ports = false {
    aws_issue["ethereum_ports"]
}

ethereum_ports_err = "Instance is communicating with ports known to mine Ethereum" {
    aws_issue["ethereum_ports"]
}

ethereum_ports_metadata := {
    "Policy Code": "",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Instance is communicating with ports known to mine Ethereum",
    "Policy Description": "Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}


#
# PR-AWS-0257-CFR
#

default dax_encrypt = null

aws_issue["dax_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dax::cluster"
    lower(resource.Properties.SSESpecification.SSEEnabled) != "true"
}

aws_bool_issue["dax_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dax::cluster"
    not resource.Properties.SSESpecification.SSEEnabled
}

dax_encrypt {
    lower(input.Resources[i].Type) == "aws::dax::cluster"
    not aws_issue["dax_encrypt"]
    not aws_bool_issue["dax_encrypt"]
}

dax_encrypt = false {
    aws_issue["dax_encrypt"]
}

dax_encrypt = false {
    aws_bool_issue["dax_encrypt"]
}

dax_encrypt_err = "Ensure DAX is securely encrypted at rest" {
    aws_issue["dax_encrypt"]
} else = "Ensure DAX is securely encrypted at rest" {
    aws_bool_issue["dax_encrypt"]
}

dax_encrypt_metadata := {
    "Policy Code": "PR-AWS-0257-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure DAX is securely encrypted at rest",
    "Policy Description": "Amazon DynamoDB Accelerator (DAX) encryption at rest provides an additional layer of data protection, helping secure your data from unauthorized access to underlying storage. With encryption at rest the data persisted by DAX on disk is encrypted using 256-bit Advanced Encryption Standard (AES-256). DAX writes data to disk as part of propagating changes from the primary node to read replicas. DAX encryption at rest automatically integrates with AWS KMS for managing the single service default key used to encrypt clusters.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dax-cluster-ssespecification.html"
}


#
# PR-AWS-0259-CFR
#

default qldb_permission_mode = null

aws_issue["qldb_permission_mode"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::qldb::ledger"
    lower(resource.Properties.PermissionsMode) != "standard"
}

aws_issue["qldb_permission_mode"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::qldb::ledger"
    not resource.Properties.PermissionsMode
}

qldb_permission_mode {
    lower(input.Resources[i].Type) == "aws::qldb::ledger"
    not aws_issue["qldb_permission_mode"]
}

qldb_permission_mode = false {
    aws_issue["qldb_permission_mode"]
}

qldb_permission_mode_err = "Ensure QLDB ledger permissions mode is set to STANDARD" {
    aws_issue["qldb_permission_mode"]
}

qldb_permission_mode_metadata := {
    "Policy Code": "PR-AWS-0259-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure QLDB ledger permissions mode is set to STANDARD",
    "Policy Description": "In Amazon Quantum Ledger Database define PermissionsMode value to STANDARD permissions mode that enables access control with finer granularity for ledgers, tables, and PartiQL commands",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html#cfn-qldb-ledger-permissionsmode"
}


#
# PR-AWS-0293-CFR
#

default secret_manager_kms = null

aws_issue["secret_manager_kms"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::secretsmanager::secret"
    not resource.Properties.KmsKeyId
}

aws_issue["secret_manager_kms"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::secretsmanager::secret"
    count(resource.Properties.KmsKeyId) == 0
}

secret_manager_kms {
    lower(input.Resources[i].Type) == "aws::secretsmanager::secret"
    not aws_issue["secret_manager_kms"]
}

secret_manager_kms = false {
    aws_issue["secret_manager_kms"]
}

secret_manager_kms_err = "Ensure that Secrets Manager secret is encrypted using KMS" {
    aws_issue["secret_manager_kms"]
}

secret_manager_kms_metadata := {
    "Policy Code": "PR-AWS-0293-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that Secrets Manager secret is encrypted using KMS",
    "Policy Description": "Ensure that your Amazon Secrets Manager secrets (i.e. database credentials, API keys, OAuth tokens, etc) are encrypted with Amazon KMS Customer Master Keys instead of default encryption keys that Secrets Manager service creates for you, in order to have a more control over secret data encryption and decryption process",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html"
}

#
# PR-AWS-0294-CFR
#

default glue_catalog_encryption = null

aws_issue["glue_catalog_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::datacatalogencryptionsettings"
    not resource.Properties.DataCatalogEncryptionSettings.ConnectionPasswordEncryption.ReturnConnectionPasswordEncrypted
}

aws_issue["glue_catalog_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::datacatalogencryptionsettings"
    lower(resource.Properties.DataCatalogEncryptionSettings.ConnectionPasswordEncryption.ReturnConnectionPasswordEncrypted) == "false"
}

aws_issue["glue_catalog_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::datacatalogencryptionsettings"
    not resource.Properties.DataCatalogEncryptionSettings.EncryptionAtRest.CatalogEncryptionMode
}

aws_issue["glue_catalog_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::datacatalogencryptionsettings"
    lower(resource.Properties.DataCatalogEncryptionSettings.EncryptionAtRest.CatalogEncryptionMode) != "sse-kms"
}

glue_catalog_encryption {
    lower(input.Resources[i].Type) == "aws::glue::datacatalogencryptionsettings"
    not aws_issue["glue_catalog_encryption"]
}

glue_catalog_encryption = false {
    aws_issue["glue_catalog_encryption"]
}

glue_catalog_encryption_err = "Ensure Glue Data Catalog encryption is enabled" {
    aws_issue["glue_catalog_encryption"]
}

glue_catalog_encryption_metadata := {
    "Policy Code": "PR-AWS-0294-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Glue Data Catalog encryption is enabled",
    "Policy Description": "Ensure that encryption at rest is enabled for your Amazon Glue Data Catalogs in order to meet regulatory requirements and prevent unauthorized users from getting access to sensitive data",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-datacatalogencryptionsettings-encryptionatrest.html"
}


#
# PR-AWS-0295-CFR
#

default codebuild_encryption = null

aws_issue["codebuild_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::codebuild::project"
    not resource.Properties.EncryptionKey
}

aws_issue["codebuild_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::codebuild::project"
    count(resource.Properties.EncryptionKey) == 0
}

codebuild_encryption {
    lower(input.Resources[i].Type) == "aws::codebuild::project"
    not aws_issue["codebuild_encryption"]
}

codebuild_encryption = false {
    aws_issue["codebuild_encryption"]
}

codebuild_encryption_err = "Ensure that CodeBuild projects are encrypted using CMK" {
    aws_issue["codebuild_encryption"]
}

codebuild_encryption_metadata := {
    "Policy Code": "PR-AWS-0295-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that CodeBuild projects are encrypted using CMK",
    "Policy Description": "The AWS Key Management Service customer master key (CMK) to be used for encrypting the build output artifacts",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html#cfn-codebuild-project-encryptionkey"
}


#
# PR-AWS-0296-CFR
#

default docdb_cluster_encrypt = null

aws_issue["docdb_cluster_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::docdb::dbcluster"
    not resource.Properties.StorageEncrypted
}

aws_issue["docdb_cluster_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::docdb::dbcluster"
    lower(resource.Properties.StorageEncrypted) == "false"
}

docdb_cluster_encrypt {
    lower(input.Resources[i].Type) == "aws::docdb::dbcluster"
    not aws_issue["docdb_cluster_encrypt"]
}

docdb_cluster_encrypt = false {
    aws_issue["docdb_cluster_encrypt"]
}

docdb_cluster_encrypt_err = "Ensure DocumentDB cluster is encrypted at rest" {
    aws_issue["docdb_cluster_encrypt"]
}

docdb_cluster_encrypt_metadata := {
    "Policy Code": "PR-AWS-0296-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure DocumentDB cluster is encrypted at rest",
    "Policy Description": "Ensure that encryption is enabled for your AWS DocumentDB (with MongoDB compatibility) clusters for additional data security and in order to meet compliance requirements for data-at-rest encryption",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-storageencrypted"
}


#
# PR-AWS-0297-CFR
#

default athena_encryption_disabling_prevent = null

aws_issue["athena_encryption_disabling_prevent"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::athena::workgroup"
    not resource.Properties.WorkGroupConfiguration.EnforceWorkGroupConfiguration
}

aws_issue["athena_encryption_disabling_prevent"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::athena::workgroup"
    lower(resource.Properties.WorkGroupConfiguration.EnforceWorkGroupConfiguration) == "false"
}

athena_encryption_disabling_prevent {
    lower(input.Resources[i].Type) == "aws::athena::workgroup"
    not aws_issue["athena_encryption_disabling_prevent"]
}

athena_encryption_disabling_prevent = false {
    aws_issue["athena_encryption_disabling_prevent"]
}

athena_encryption_disabling_prevent_err = "Ensure to enable EnforceWorkGroupConfiguration for athena workgroup" {
    aws_issue["athena_encryption_disabling_prevent"]
}

athena_encryption_disabling_prevent_metadata := {
    "Policy Code": "PR-AWS-0297-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure to enable EnforceWorkGroupConfiguration for athena workgroup",
    "Policy Description": "Athena workgroups support the ability for clients to override configuration options, including encryption requirements. This setting should be disabled to enforce encryption mandates",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-storageencrypted"
}


#
# PR-AWS-302-CFR
#

default log_group_encryption = null

aws_issue["log_group_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::logs::loggroup"
    not resource.Properties.KmsKeyId
}

aws_issue["log_group_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::logs::loggroup"
    count(resource.Properties.KmsKeyId) == 0
}

aws_issue["log_group_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::logs::loggroup"
    resource.Properties.KmsKeyId == null
}

log_group_encryption {
    lower(input.Resources[i].Type) == "aws::logs::loggroup"
    not aws_issue["log_group_encryption"]
}

log_group_encryption = false {
    aws_issue["log_group_encryption"]
}

log_group_encryption_err = "Ensure CloudWatch log groups are encrypted with KMS CMKs" {
    aws_issue["log_group_encryption"]
}

log_group_encryption_metadata := {
    "Policy Code": "PR-AWS-302-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure CloudWatch log groups are encrypted with KMS CMKs",
    "Policy Description": "CloudWatch log groups are encrypted by default. However, utilizing KMS CMKs gives you more control over key rotation and provides auditing visibility into key usage.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html"
}

#
# PR-AWS-303-CFR
#

default log_group_retention = null

aws_issue["log_group_retention"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::logs::loggroup"
    not resource.Properties.RetentionInDays
}

log_group_retention {
    lower(input.Resources[i].Type) == "aws::logs::loggroup"
    not aws_issue["log_group_retention"]
}

log_group_retention = false {
    aws_issue["log_group_retention"]
}

log_group_retention_err = "Ensure CloudWatch log groups has retention days defined" {
    aws_issue["log_group_retention"]
}

log_group_retention_metadata := {
    "Policy Code": "PR-AWS-303-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure CloudWatch log groups has retention days defined",
    "Policy Description": "Ensure that your web-tier CloudWatch log group has the retention period feature configured in order to establish how long log events are kept in AWS CloudWatch Logs",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html"
}


#
# PR-AWS-304-CFR
#

default timestream_database_encryption = null

aws_issue["timestream_database_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::timestream::database"
    not resource.Properties.KmsKeyId
}

aws_issue["timestream_database_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::timestream::database"
    count(resource.Properties.KmsKeyId) == 0
}

aws_issue["timestream_database_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::timestream::database"
    resource.Properties.KmsKeyId == null
}

timestream_database_encryption {
    lower(input.Resources[i].Type) == "aws::logs::loggroup"
    not aws_issue["timestream_database_encryption"]
}

timestream_database_encryption = false {
    aws_issue["timestream_database_encryption"]
}

timestream_database_encryption_err = "Ensure Timestream database is encrypted using KMS" {
    aws_issue["timestream_database_encryption"]
}

timestream_database_encryption_metadata := {
    "Policy Code": "PR-AWS-304-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Timestream database is encrypted using KMS",
    "Policy Description": "The timestream databases must be secured with KMS instead of default kms.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-database.html#cfn-timestream-database-kmskeyid"
}


#
# PR-AWS-0307-CFR
#

default workspace_volume_encrypt = null

aws_issue["workspace_volume_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::workspaces::workspace"
    not resource.Properties.UserVolumeEncryptionEnabled
}

aws_issue["workspace_volume_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::workspaces::workspace"
    lower(resource.Properties.UserVolumeEncryptionEnabled) == "false"
}

workspace_volume_encrypt {
    lower(input.Resources[i].Type) == "aws::workspaces::workspace"
    not aws_issue["workspace_volume_encrypt"]
}

workspace_volume_encrypt = false {
    aws_issue["workspace_volume_encrypt"]
}

workspace_volume_encrypt_err = "Ensure that Workspace user volumes is encrypted" {
    aws_issue["workspace_volume_encrypt"]
}

workspace_volume_encrypt_metadata := {
    "Policy Code": "PR-AWS-0307-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that Workspace user volumes is encrypted",
    "Policy Description": "Ensure that your Amazon WorkSpaces storage volumes are encrypted in order to meet security and compliance requirements. Your data is transparently encrypted while being written and transparently decrypted while being read from your storage volumes, therefore the encryption process does not require any additional action from you",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-workspaces-workspace.html"
}


#
# PR-AWS-0308-CFR
#

default codebuild_encryption_disable = null

aws_issue["codebuild_encryption_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::codebuild::project"
    resource.Properties.Artifacts.EncryptionDisabled == true
}

aws_issue["codebuild_encryption_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::codebuild::project"
    lower(resource.Properties.Artifacts.EncryptionDisabled) == "true"
}

codebuild_encryption_disable {
    lower(input.Resources[i].Type) == "aws::codebuild::project"
    not aws_issue["codebuild_encryption_disable"]
}

codebuild_encryption_disable = false {
    aws_issue["codebuild_encryption_disable"]
}

codebuild_encryption_disable_err = "Ensure CodeBuild project Artifact encryption is not disabled" {
    aws_issue["codebuild_encryption_disable"]
}

codebuild_encryption_disable_metadata := {
    "Policy Code": "PR-AWS-0308-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure CodeBuild project Artifact encryption is not disabled",
    "Policy Description": "AWS CodeBuild is a fully managed build service in the cloud. CodeBuild compiles your source code, runs unit tests, and produces artifacts that are ready to deploy. Build artifacts, such as a cache, logs, exported raw test report data files, and build results, are encrypted by default using CMKs for Amazon S3 that are managed by the AWS Key Management Service. If you do not want to use these CMKs, you must create and configure a customer-managed CMK.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codebuild-project-artifacts.html#cfn-codebuild-project-artifacts-encryptiondisabled"
}


#
# PR-AWS-0311-CFR
#

default glue_security_config = null

aws_issue["glue_security_config_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    not resource.Properties.EncryptionConfiguration
}

aws_issue["glue_security_config_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(resource.Properties.EncryptionConfiguration.CloudWatchEncryption.CloudWatchEncryptionMode) != "SSE-KMS"
}

aws_issue["glue_security_config_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(resource.Properties.EncryptionConfiguration.JobBookmarksEncryption.JobBookmarksEncryptionMode) != "SSE-KMS"
}

aws_issue["glue_security_config_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(resource.Properties.EncryptionConfiguration.S3Encryptions.S3EncryptionMode) != "SSE-KMS"
}

glue_security_config {
    lower(input.Resources[i].Type) == "aws::glue::securityconfiguration"
    not aws_issue["glue_security_config"]
}

glue_security_config = false {
    aws_issue["glue_security_config"]
}

glue_security_config_err = "Ensure AWS Glue security configuration encryption is enabled" {
    aws_issue["glue_security_config"]
}

glue_security_config_metadata := {
    "Policy Code": "PR-AWS-0311-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS Glue security configuration encryption is enabled",
    "Policy Description": "Ensure AWS Glue security configuration encryption is enabled",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-securityconfiguration-encryptionconfiguration.html#cfn-glue-securityconfiguration-encryptionconfiguration-s3encryptions"
}

#
# PR-AWS-0319-CFR
#

default backup_public_access_disable = null

aws_issue["backup_public_access_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::backup::backupvault"
    statement := resource.Properties.AccessPolicy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
}

aws_issue["backup_public_access_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::backup::backupvault"
    statement := resource.Properties.AccessPolicy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
}

aws_issue["backup_public_access_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::backup::backupvault"
    statement := resource.Properties.AccessPolicy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
}


backup_public_access_disable {
    lower(input.Resources[i].Type) == "aws::backup::backupvault"
    not aws_issue["backup_public_access_disable"]
}

backup_public_access_disable = false {
    aws_issue["backup_public_access_disable"]
}

backup_public_access_disable_err = "Ensure Glacier Backup policy is not publicly accessible" {
    aws_issue["backup_public_access_disable"]
}

backup_public_access_disable_metadata := {
    "Policy Code": "PR-AWS-0319-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Glacier Backup policy is not publicly accessible",
    "Policy Description": "Public Glacier backup potentially expose existing interfaces to unwanted 3rd parties that can tap into an existing data stream, resulting in data leak to an unwanted party.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupvault.html#cfn-backup-backupvault-accesspolicy"
}


#
# PR-AWS-0328-CFR
#

default neptune_cluster_logs = null

aws_issue["neptune_cluster_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::neptune::dbcluster"
    not resource.Properties.EnableCloudwatchLogsExports
}

aws_issue["neptune_cluster_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::neptune::dbcluster"
    count(resource.Properties.EnableCloudwatchLogsExports) == 0
}

neptune_cluster_logs {
    lower(input.Resources[i].Type) == "aws::neptune::dbcluster"
    not aws_issue["neptune_cluster_logs"]
}

neptune_cluster_logs = false {
    aws_issue["neptune_cluster_logs"]
}

neptune_cluster_logs_err = "Ensure Neptune logging is enabled" {
    aws_issue["neptune_cluster_logs"]
}

neptune_cluster_logs_metadata := {
    "Policy Code": "PR-AWS-0328-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Neptune logging is enabled",
    "Policy Description": "These access logs can be used to analyze traffic patterns and troubleshoot security and operational issues.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-neptune-dbcluster.html#cfn-neptune-dbcluster-enablecloudwatchlogsexports"
}


#
# PR-AWS-0329-CFR
#

default docdb_cluster_logs = null

aws_issue["docdb_cluster_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::docdb::dbcluster"
    not resource.Properties.EnableCloudwatchLogsExports
}

aws_issue["docdb_cluster_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::docdb::dbcluster"
    count(resource.Properties.EnableCloudwatchLogsExports) == 0
}

docdb_cluster_logs {
    lower(input.Resources[i].Type) == "aws::docdb::dbcluster"
    not aws_issue["docdb_cluster_logs"]
}

docdb_cluster_logs = false {
    aws_issue["docdb_cluster_logs"]
}

docdb_cluster_logs_err = "Ensure AWS DocumentDB logging is enabled" {
    aws_issue["docdb_cluster_logs"]
}

docdb_cluster_logs_metadata := {
    "Policy Code": "PR-AWS-0329-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS DocumentDB logging is enabled",
    "Policy Description": "The events recorded by the AWS DocumentDB audit logs include: successful and failed authentication attempts, creating indexes or dropping a collection in a database within the DocumentDB cluster.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-enablecloudwatchlogsexports"
}