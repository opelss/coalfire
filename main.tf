#------------+
# Main Stack
#------------+

#--------+
# Locals
#--------+

locals {
  apache_user_data = <<-EOF
    #!/bin/bash
    dnf update -y
    dnf install -y httpd
    systemctl enable httpd
    systemctl start httpd

    echo "<h1>RHEL + Apache installed by Terraform</h1>" > /var/www/html/index.html
  EOF
}

#-------------------------+
# Networking requirements
#-------------------------+
# 1 VPC – 10.1.0.0/16
# 4 subnets (spread evenly across two availability zones)
# Sub1 – 10.1.0.0/24 (should be accessible from internet)
# Sub2 – 10.1.1.0/24 (should be accessible from internet)
# Sub3 – 10.1.2.0/24 (should NOT be accessible from internet)
# Sub4 – 10.1.3.0/24 (should NOT be accessible from internet)
# Security groups should be used to allow necessary traffic

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = "demo-vpc"
  cidr = "10.1.0.0/16"

  azs                  = ["eu-west-1a", "eu-west-1b"]
  public_subnet_names  = ["Sub1", "Sub2"]
  public_subnets       = ["10.1.0.0/24", "10.1.1.0/24"]
  private_subnet_names = ["Sub3", "Sub4"]
  private_subnets      = ["10.1.2.0/24", "10.1.3.0/24"]

  enable_nat_gateway = true
  enable_vpn_gateway = true

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

#-----+
# Data
#-----+

data "aws_subnet" "by_name_sub2" {
  filter {
    name   = "tag:Name"
    values = ["Sub2"]
  }
}

#----+
# SG
#----+

resource "aws_security_group" "web_server_sg" {
  name        = "web-server-sg"
  description = "Allow inbound HTTP/S traffic to web servers"
  vpc_id      = data.aws_subnet.by_name_sub2.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Allow from all IPv4 addresses
    description = "Allow HTTP from anywhere"
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Allow from all IPv4 addresses
    description = "Allow HTTPS from anywhere"
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "web-server-sg"
  }
}

#-------------------------+
# S3 "Images" requirements
#-------------------------+
# 1 S3 bucket: “Images” with a folder called archive
# “Memes” folder - move objects older than 90 days to glacier.

module "s3_bucket_images" {
  source = "terraform-aws-modules/s3-bucket/aws"

  bucket = "Images"
  acl    = "private"

  control_object_ownership = true
  object_ownership         = "ObjectWriter"

  versioning = {
    enabled = true
  }
}

resource "aws_s3_object" "folder_archive" {
  bucket = module.s3_bucket_images.name
  key    = "archive"
}

resource "aws_s3_object" "folder_memes" {
  bucket = module.s3_bucket_images.name
  key    = "Memes"
}

resource "aws_s3_bucket_lifecycle_configuration" "archive_glacier_memes" {
  bucket = module.s3_bucket_images.name

  rule {
    id     = "archive-to-glacier-after-90-days"
    status = "Enabled"

    filter {
      prefix = "Memes/"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }
}


#------------------------+
# S3 "Logs" requirements:
#------------------------+
# 1 S3 bucket: “Logs” with two folders and the following lifecycle policies
# “Active folder” - move objects older than 90 days to glacier.
# “Inactive folder” - delete objects older than 90 days.

module "s3_bucket_logs" {
  source = "terraform-aws-modules/s3-bucket/aws"

  bucket = "Logs"
  acl    = "private"

  control_object_ownership = true
  object_ownership         = "ObjectWriter"

  versioning = {
    enabled = true
  }
}

resource "aws_s3_object" "folder_active" {
  bucket = module.s3_bucket_logs.name
  key    = "Active"
}

resource "aws_s3_object" "folder_inactive" {
  bucket = module.s3_bucket_logs.name
  key    = "Inactive"
}

resource "aws_s3_bucket_lifecycle_configuration" "archive_glacier_active" {
  bucket = module.s3_bucket_logs.name

  rule {
    id     = "archive-to-glacier-after-90-days"
    status = "Enabled"

    filter {
      prefix = "Active/"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "archive_delete" {
  bucket = module.s3_bucket_logs.name

  rule {
    id     = "delete-after-90-days"
    status = "Enabled"

    filter {
      prefix = "Inactive/"
    }

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

#-----------------+
# IAM requirements
#-----------------+
# An IAM role that can write to the logs to log bucket from ALL EC2s provisioned.

resource "aws_iam_role" "ec2_logs_role" {
  name = "ec2-logs-writer"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role" "ec2_logs_images_role" {
  name = "ec2-logs-images-reader"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "ec2_logs_policy" {
  name = "ec2-write-logs-to-s3"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        Resource = "arn:aws:s3:::${module.s3_bucket_logs.name}/Active/*"
      }
    ]
  })
}

resource "aws_iam_policy" "ec2_images_read_policy" {
  name = "ec2-images-from-s3"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Allow listing ONLY the images prefix
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = "arn:aws:s3:::${module.s3_bucket_images.name}"
        Condition = {
          StringLike = {
            "s3:prefix" = [
              "/*"
            ]
          }
        }
      },

      # Allow reading objects
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = "arn:aws:s3:::${module.s3_bucket_images.name}/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_logs_attach" {
  role       = aws_iam_role.ec2_logs_role.name
  policy_arn = aws_iam_policy.ec2_logs_policy.arn
}

resource "aws_iam_role_policy_attachment" "ec2_logs_attach_2" {
  role       = aws_iam_role.ec2_logs_images_role.name
  policy_arn = aws_iam_policy.ec2_logs_policy.arn
}

resource "aws_iam_role_policy_attachment" "ec2_images_reader_attach" {
  role       = aws_iam_role.ec2_logs_images_role.name
  policy_arn = aws_iam_policy.ec2_images_read_policy.arn
}

resource "aws_iam_instance_profile" "ec2_logs_profile" {
  name = "ec2-logs-writer-profile"
  role = aws_iam_role.ec2_logs_role.name
}

resource "aws_iam_instance_profile" "ec2_logs_images_profile" {
  name = "ec2_logs_images_profile"
  role = aws_iam_role.ec2_logs_images_role.name
}

#-----------------+
# EC2 requirements
#-----------------+
# 1 EC2 instance running Red Hat Linux in subnet sub2
# 20 GB storage
# t2.micro

module "ec2_instance" {
  source = "terraform-aws-modules/ec2-instance/aws"

  name                 = "single-instance"
  iam_instance_profile = aws_iam_instance_profile.ec2_logs_profile.name

  ami                    = "RHEL-9.5.0_HVM-20250313-x86_64-0-Hourly2-GP3"
  instance_type          = "t2.micro"
  key_name               = "user1"
  monitoring             = true
  subnet_id              = data.aws_subnet.by_name_sub2.id
  vpc_security_group_ids = [aws_security_group.web_server_sg.id]
  user_data              = local.apache_user_data

  root_block_device = {
    encrypted  = true
    type       = "gp3"
    throughput = 200
    size       = 20
    tags = {
      Name = "root-block-device"
    }
  }

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

#-----------------+
# ASG requirements
#-----------------+
# 1 auto scaling group (ASG) that will spread out instances across subnets sub3 and sub4
# Use Red Hat Linux
# 20 GB storage
# Script the installation of Apache web server (httpd) on these instances
# Add an IAM role to your ASG hosts that can read from the "images" bucket
# 2 minimum, 6 maximum hosts
# t2.micro

module "asg" {
  source = "terraform-aws-modules/autoscaling/aws"

  # Autoscaling group
  name = "example-asg"

  vpc_zone_identifier       = module.vpc.private_subnets
  min_size                  = 2
  max_size                  = 6
  desired_capacity          = 2
  instance_type             = "t2.micro"
  image_id                  = "RHEL-9.5.0_HVM-20250313-x86_64-0-Hourly2-GP3"
  user_data                 = local.apache_user_data
  security_groups           = [aws_security_group.web_server_sg.id]
  iam_instance_profile_name = aws_iam_instance_profile.ec2_logs_images_profile.name
  block_device_mappings = [
    {
      # Root volume
      device_name = "/dev/xvda"
      no_device   = 0
      ebs = {
        delete_on_termination = true
        encrypted             = true
        volume_size           = 20
        volume_type           = "gp2"
      }
    }
  ]
}

#-----------------+
# ABL requirements
#-----------------+
# 1 application load balancer (ALB) that listens on TCP port 80 (HTTP) and forwards traffic to the ASG in subnets sub3 and sub4 on port 443

module "alb" {
  source = "terraform-aws-modules/alb/aws"

  name    = "demo-alb"
  vpc_id  = data.aws_subnet.by_name_sub2.vpc_id
  subnets = ["Sub3", "Sub4"]

  # Security Group
  security_group_ingress_rules = {
    all_http = {
      from_port   = 80
      to_port     = 80
      ip_protocol = "tcp"
      description = "HTTP web traffic"
      cidr_ipv4   = "0.0.0.0/0"
    }
    all_https = {
      from_port   = 443
      to_port     = 443
      ip_protocol = "tcp"
      description = "HTTPS web traffic"
      cidr_ipv4   = "0.0.0.0/0"
    }
  }
  security_group_egress_rules = {
    all = {
      ip_protocol = "-1"
      cidr_ipv4   = "10.0.0.0/16"
    }
  }

  listeners = {
    ex-http-https-redirect = {
      port     = 80
      protocol = "HTTP"
      redirect = {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
    ex-https = {
      port            = 443
      protocol        = "HTTPS"
      certificate_arn = "arn:aws:iam::123456789012:server-certificate/test_cert-123456789012" #Demo cert

      forward = {
        target_group_arn = module.asg.autoscaling_group_target_group_arns
      }
    }
  }

  tags = {
    Environment = "Development"
    Project     = "Example"
  }
}
