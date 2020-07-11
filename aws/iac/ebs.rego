package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-ebs-volume.html

#
# Id: 41
#

default ebs_encrypt = null

ebs_encrypt {
    lower(input.Type) == "aws::ec2::volume"
    input.Properties.Encrypted == true
}

ebs_encrypt = false {
    lower(input.Type) == "aws::ec2::volume"
    input.Properties.Encrypted == false
}

ebs_encrypt_err = "AWS EBS volumes are not encrypted" {
    ebs_encrypt == false
}
