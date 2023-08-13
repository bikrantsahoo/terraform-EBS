# provider and profile
provider "aws" {
  profile = "bikrant"
  region  = "ap-south-1"
}

# default vpc
resource "aws_default_vpc" "default_vpc" {
  tags = {
    Name = "Default VPC"
  }
}

# key variable
variable "key_name" {
  default = "ec2Key"
}

# base_path variable
variable "base_path" {
  default = "/home/krajpurohit/terra-infra/"
}

# private key 
resource "tls_private_key" "private_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# aws keypair
resource "aws_key_pair" "key_pair" {
  key_name   = var.key_name
  public_key = tls_private_key.private_key.public_key_openssh

   depends_on = [tls_private_key.private_key]
}

# save privateKey
resource "local_file" "saveKey" {
  content = tls_private_key.private_key.private_key_pem
  filename = "${var.base_path}${var.key_name}.pem"
  
}

# security group
resource "aws_security_group" "security_group" {
  name        = "allow_tcp"
  description = "Allow tcp inbound traffic"
  vpc_id      = aws_default_vpc.default_vpc.id

  ingress {
    description = "Allow Jenkins"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description = "Allow HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description = "Allow HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description = "Allow SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "allow_tcp"
  }
}

# ec2 instance
resource "aws_instance" "ec2_instance" {
  depends_on = [aws_key_pair.key_pair,aws_security_group.security_group]
  ami                    = "ami-0447a12f28fddb066"
  instance_type          = "t2.micro"
  key_name               = var.key_name
  security_groups = [aws_security_group.security_group.name]
  tags = {
    Name = "webServer"
  }
}

# ebs volume
resource "aws_ebs_volume" "ebs_volume" {
  availability_zone = aws_instance.ec2_instance.availability_zone
  size              = 1
  tags = {
    Name = "ebsVolume"
  }
}

# attach ebs volume
resource "aws_volume_attachment" "attach_volume" {
  depends_on = [aws_instance.ec2_instance,aws_ebs_volume.ebs_volume]
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.ebs_volume.id
  instance_id = aws_instance.ec2_instance.id
  force_detach = true
}

# provisioner to execute ansible playbook
resource "null_resource" "configure_server"{

depends_on = [aws_instance.ec2_instance,aws_ebs_volume.ebs_volume,aws_volume_attachment.attach_volume]
provisioner "local-exec"{
  command = "chmod 400 ${var.base_path}${var.key_name}.pem"
  }
provisioner "local-exec"{
  command = "ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -u ec2-user --private-key ${var.base_path}${var.key_name}.pem -i '${aws_instance.ec2_instance.public_ip},' playbook.yml"
  }
}

# s3 bucket
resource "aws_s3_bucket" "s3_bucket" {
  bucket = "kr-webserver-static"
  acl    = "private"

  tags = {
    Name = "static files bucket"
  }
}

# block bucket public access
resource "aws_s3_bucket_public_access_block" "s3_block_access" {
  depends_on = [aws_s3_bucket.s3_bucket]
  bucket = aws_s3_bucket.s3_bucket.id
  block_public_acls   = true
  block_public_policy = true
  restrict_public_buckets = true
  ignore_public_acls = true
}

# s3 bucket origin id 
locals {
  s3_origin_id = "s3Origin"
}


# origin access identity for distribution
resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
comment = "cloudfront distribution identity"
}

# distribution
resource "aws_cloudfront_distribution" "distribution" {
  depends_on = [aws_s3_bucket.s3_bucket,aws_s3_bucket_public_access_block.s3_block_access]
  origin {
    domain_name = aws_s3_bucket.s3_bucket.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
  origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "cloudfront for static content"


  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

# create s3 policy to allow distribution to read objects
data "aws_iam_policy_document" "s3_policy" {
  depends_on = [aws_s3_bucket.s3_bucket,aws_cloudfront_distribution.distribution]
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.s3_bucket.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
    }
  }

  statement {
    actions   = ["s3:ListBucket"]
    resources = ["${aws_s3_bucket.s3_bucket.arn}"]

    principals {
      type        = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
    }
  }
}

# updating bucket policy for distribution
resource "aws_s3_bucket_policy" "update_s3_policy" {
  depends_on = [aws_s3_bucket.s3_bucket]
  bucket = aws_s3_bucket.s3_bucket.id
  policy = data.aws_iam_policy_document.s3_policy.json
}

# provisioner to upload all object to bucket 
# or either run the command in your asset directory

# resource "null_resource" "remove_and_upload_to_s3" {
#   provisioner "local-exec" {
#     command = "aws s3 cp ${var.base_path}assets/ s3://${aws_s3_bucket.s3_bucket.id} --recursive"
#   }
# }

# instance ip
output "instance_ip" {
  value = aws_instance.ec2_instance.public_ip
}

# distribution id
output "distribution_domain" {
  value = aws_cloudfront_distribution.distribution.domain_name
}
