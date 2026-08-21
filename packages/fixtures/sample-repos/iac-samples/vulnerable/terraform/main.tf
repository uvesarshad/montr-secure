provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE1"
  secret_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY1"
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "admin" {
  name = "admin-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_s3_bucket" "data" {
  bucket = "my-app-data-bucket"
}

resource "aws_db_instance" "main" {
  allocated_storage = 20
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  username          = "admin"
  password          = "SuperSecretDbPass1"
  storage_encrypted = false
}
