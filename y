version = 0.1
[default]
[default.deploy]
[default.deploy.parameters]
stack_name = "sam-app"
s3_bucket = "aws-sam-cli-managed-default-samclisourcebucket-j8zjb0pbu6qc"
s3_prefix = "sam-app"
region = "us-east-1"
capabilities = "CAPABILITY_IAM"
disable_rollback = true
image_repositories = []
confirm_changeset = true

[y]
[y.deploy]
[y.deploy.parameters]
stack_name = "sam-app"
s3_bucket = "aws-sam-cli-managed-default-samclisourcebucket-j8zjb0pbu6qc"
s3_prefix = "sam-app"
region = "us-east-1"
confirm_changeset = true
capabilities = "CAPABILITY_IAM"
disable_rollback = true
image_repositories = []
