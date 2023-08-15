    # creating a bucket for storing artifacts, with server side encryption enabled.
resource "aws_s3_bucket" "code_pipeline_artifact_store_bucket" {
  bucket = "${var.stack_name}-artifact-bucket"
  
  tags = {
    "pipeline-name" = "${var.stack_name}-pipeline"
  }
}

# S3bucket poilicy is attached to resource(S3 bucket) "CodePipelineArtifactStoreBucket"
    # To deny if object server side encryption is not enabled with header
    # To deny all actions if transport security (SSL/TLS) is not enabled (i.e, aws:SecureTransport: false)

resource "aws_s3_bucket_policy" "code_pipeline_artifact_store_bucket_policy" {
  bucket = aws_s3_bucket.code_pipeline_artifact_store_bucket.bucket

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "DenyUnEncryptedObjectUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = [
          "arn:aws:s3:::${aws_s3_bucket.code_pipeline_artifact_store_bucket.bucket}/*",
          "arn:aws:s3:::${aws_s3_bucket.code_pipeline_artifact_store_bucket.bucket}"
        ]
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid       = "DenyInsecureConnections"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          "arn:aws:s3:::${aws_s3_bucket.code_pipeline_artifact_store_bucket.bucket}/*",
          "arn:aws:s3:::${aws_s3_bucket.code_pipeline_artifact_store_bucket.bucket}"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

variable "stack_name" {
  description = "The name of the AWS stack"
  default     = "default-stack-name" # You can modify this default or provide the value when running terraform
}

###Cloud watch event role 
resource "aws_iam_role" "AmazonCloudWatchEventRole" {
  name               = "AmazonCloudWatchEventRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Principal = {
          Service = "events.amazonaws.com"
        }
      }
    ]
  })

  inline_policy {
    name   = "cwe-pipeline-execution"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect   = "Allow"
          Action   = "codepipeline:StartPipelineExecution"
          Resource = "arn:aws-us-gov:codepipeline:${var.AWS_Region}:${var.AWS_AccountId}:${var.AppPipeline}"
        }
      ]
    })
  }
}

 ### Cloudwatch event to trigger the pipeline on commit
resource "aws_cloudwatch_event_rule" "AmazonCloudWatchEventRule" {
  name        = "AmazonCloudWatchEventRule"
  description = "Cloudwatch event to trigger the pipeline on commit"

  event_pattern = jsonencode({
    source = ["aws.codecommit"]
    "detail-type" = ["CodeCommit Repository State Change"]
    resources = ["arn:aws-us-gov:codecommit:${var.AWS_Region}:${var.AWS_AccountId}:${var.RepositoryName}"]
    detail = {
      event = ["referenceCreated", "referenceUpdated"]
      referenceType = ["branch"]
      referenceName = ["master"]
    }
  })

  role_arn = aws_iam_role.AmazonCloudWatchEventRole.arn
}
resource "aws_cloudwatch_event_target" "codepipeline_target" {
  rule      = aws_cloudwatch_event_rule.AmazonCloudWatchEventRule.name
  target_id = "codepipeline-AppPipeline"
  arn       = "arn:aws-us-gov:codepipeline:${var.AWS_Region}:${var.AWS_AccountId}:${var.AppPipeline}"
  role_arn  = aws_iam_role.AmazonCloudWatchEventRole.arn
}

###Cloudwatch event rule for SNS notifications for pipeline state change
resource "aws_cloudwatch_event_rule" "CloudWatchPipelineEventRule" {
  name        = "CloudWatchPipelineEventRule"
  description = "Cloudwatch event rule for SNS notifications for pipeline state change"

  event_pattern = jsonencode({
    source = ["aws.codepipeline"]
    "detail-type" = ["CodePipeline Stage Execution State Change"]
  })
}

resource "aws_cloudwatch_event_target" "pipeline_notifications" {
  rule      = aws_cloudwatch_event_rule.CloudWatchPipelineEventRule.name
  target_id = "PipelineNotifications"
  arn       = var.PipelineTopic
}

###Cloudtrail event notifications for pipeline updates, deletes, and codebuild project creation, deletion, etc.
resource "aws_s3_bucket" "TrailBucket" {
  bucket = "trailbucket-name"
  tags = {
    "pipeline-name" = "${var.AWS_StackName}-pipeline"
  }
}

resource "aws_s3_bucket_policy" "TrailBucketPolicy" {
  bucket = aws_s3_bucket.TrailBucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    #... the remaining statements from the bucket policy ...
  })
}


resource "aws_s3_bucket_policy" "trail_bucket_policy" {
  bucket = aws_s3_bucket.trail_bucket.id

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = "arn:aws-us-gov:s3:::${aws_s3_bucket.trail_bucket.id}"
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "arn:aws-us-gov:s3:::${aws_s3_bucket.trail_bucket.id}/AWSLogs/${var.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid       = "AllowSSLRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = "${aws_s3_bucket.trail_bucket.arn}/*"
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "trail" {
  depends_on = [aws_s3_bucket_policy.trail_bucket_policy]

  name                          = "trail-name" # Change as needed
  s3_bucket_name                = aws_s3_bucket.trail_bucket.bucket
  include_global_service_events = true
  enable_logging                = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = aws_cloudwatch_log_group.trail_log_group.arn
  cloud_watch_logs_role_arn     = aws_iam_role.trail_log_group_role.arn
}

resource "aws_cloudwatch_log_group" "trail_log_group" {
  name              = "trail-log-group-name" # Change as needed
  retention_in_days = 90
}

resource "aws_iam_role" "trail_log_group_role" {
  name = "trail-log-group-role-name" # Change as needed

  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Sid      = "AssumeRole1"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "trail_log_group_role_policy" {
  name   = "cloudtrail-policy"
  role   = aws_iam_role.trail_log_group_role.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = aws_cloudwatch_log_group.trail_log_group.arn
      }
    ]
  })
}

resource "aws_cloudwatch_log_metric_filter" "pipeline_state_change_metric_filter" {
  name           = "pipeline-state-change-metric-filter-name" # Change as needed
  pattern        = "{ ($.eventName = \"StartPipelineExecution\") || ($.eventName = \"StopPipelineExecution\") || ($.eventName = \"UpdatePipeline\") || ($.eventName = \"DeletePipeline\") }"
  log_group_name = aws_cloudwatch_log_group.trail_log_group.name

  metric_transformation {
    name      = "pipelineEvent"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "pipeline_state_change_alarm" {
  alarm_name          = "${var.stack_name}-CloudTrailPipelineEventChange"
  alarm_description   = "Alarm when cloudtrail receives a state change event from codepipeline"
  metric_name         = "pipelineEvent"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = 0
  namespace           = "CloudTrailMetrics"
  statistic           = "Sum"
  period              = 1800

  alarm_actions = [var.cloudtrail_topic] # Set the ARN or ID of the SNS topic
}

variable "stack_name" {
  description = "The name of the AWS Stack"
  default     = "default-stack-name" # Change as needed
}

variable "account_id" {
  description = "The AWS Account ID"
  default     = "your-account-id" # Change as needed
}

variable "cloudtrail_topic" {
  description = "The ARN or ID of the SNS topic for CloudTrail"
  default     = "your-sns-topic-arn-or-id" # Change as needed
}


#codebuild_change_metric_filter
resource "aws_cloudwatch_log_metric_filter" "codebuild_change_metric_filter" {
  name           = "CodeBuildChangeMetricFilter"
  pattern        = "{ (($.eventSource = \"codebuild.amazonaws.com\") && (($.eventName = \"CreateProject\") || ($.eventName = \"DeleteProject\"))) }"
  log_group_name = aws_cloudwatch_log_group.trail_log_group.name
  
  metric_transformation {
    name      = "codebuildEvent"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "codebuild_state_change_alarm" {
  alarm_name          = "${aws_cloudformation_stack.stack_name.id}-CloudTrailCodebuildEventChange"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "codebuildEvent"
  namespace           = "CloudTrailMetrics"
  period              = "1800"
  statistic           = "Sum"
  threshold           = "0"

  alarm_description = "Alarm when cloudtrail receives an state change event from codebuild"
  alarm_actions     = [aws_sns_topic.cloudtrail_topic.arn]
}

resource "aws_cloudwatch_log_group" "trail_log_group" {
  name = "your-log-group-name-here"
}

resource "aws_sns_topic" "cloudtrail_topic" {
  name = "your-sns-topic-name-here"
}

resource "aws_cloudformation_stack" "stack_name" {
  # This resource is here just for the reference in alarm_name.
  # In actual Terraform, if you are not managing a CloudFormation stack, you'd replace it with a direct variable or appropriate reference.
}


 ### AWS Config rules

 resource "aws_config_config_rule" "rule1" {
  name        = "${local.stack_name}-codebuild-project-envvar-awscred-check"
  description = "Checks whether the project contains environment variables AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY. The rule is NON_COMPLIANT when the project environment variables contains plaintext credentials."

  source {
    owner             = "AWS"
    source_identifier = "CODEBUILD_PROJECT_ENVVAR_AWSCRED_CHECK"
  }

  scope {
    compliance_resource_types = ["AWS::CodeBuild::Project"]
  }

  depends_on = [aws_config_configuration_recorder.foo]
}

resource "aws_config_config_rule" "rule2" {
  name        = "${local.stack_name}-codebuild-project-source-repo-url-check"
  description = "Checks whether the GitHub or Bitbucket source repository URL contains either personal access tokens or user name and password. The rule is complaint with the usage of OAuth to grant authorization for accessing GitHub or Bitbucket repositories."

  source {
    owner             = "AWS"
    source_identifier = "CODEBUILD_PROJECT_SOURCE_REPO_URL_CHECK"
  }

  scope {
    compliance_resource_types = ["AWS::CodeBuild::Project"]
  }

  depends_on = [aws_config_configuration_recorder.foo]
}

resource "aws_config_config_rule" "rule3" {
  name        = "${local.stack_name}-cloud-trail-log-file-validation-enabled"
  description = "Checks whether AWS CloudTrail creates a signed digest file with logs. AWS recommends that the file validation must be enabled on all trails. The rule is noncompliant if the validation is not enabled."

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.foo]
}

locals {
  stack_name = "YourStackNameHere"
}

resource "aws_config_configuration_recorder" "foo" {
  name     = "example"
  role_arn = aws_iam_role.r.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_iam_role" "r" {
  name = "my-awsconfig-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Principal = {
          Service = "config.amazonaws.com"
        },
        Effect = "Allow",
        Sid    = ""
      }
    ]
  })
}

 #### Codepipeline creation 

resource "aws_codepipeline" "app_pipeline" {
  name     = "${aws_cloudformation_stack.this.name}-pipeline"
  role_arn = aws_iam_role.pipeline_service_role.arn

  artifact_store {
    location = aws_s3_bucket.codepipeline_bucket.bucket
    type     = "S3"
  }

  stage {
    name = "Source"

    action {
      name             = "SourceAction"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeCommit"
      version          = "1"
      output_artifacts = ["SourceOutput"]

      configuration = {
        BranchName            = var.BranchName
        RepositoryName        = var.RepositoryName
        PollForSourceChanges  = false
      }

      run_order = 1
    }
  }

### Actual blog Pipeline stages 

  stage {
    name = "Build-Secrets"

    action {
      name             = "Secret-Analysis"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["SourceOutput"]
      output_artifacts = ["SecArtifacts"]

      configuration = {
        ProjectName = var.SecBuildProject
      }

      run_order = 2
    }
  }

  stage {
    name = "Build-SAST"

    action {
      name             = "SAST-Analysis"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["SourceOutput"]
      output_artifacts = ["SASTArtifacts"]

      configuration = {
        ProjectName = var.SASTBuildProject
      }

      run_order = 3
    }

    action {
      name             = "ECR-SAST-and-STG-Deploy"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["SourceOutput"]
      output_artifacts = ["ECRSASTArtifacts"]

      configuration = {
        ProjectName = var.ECRSASTBuildProject
      }

      run_order = 4
    }
  }
}

 ### Build stage for DAST analysis with OWASP Zap  


  stage {
    name = "Build-DAST"

    action {
      name            = "DASTAnalysis"
      category        = "Test"
      owner           = "AWS"
      provider        = "CodeBuild"
      version         = "1"
      input_artifacts = ["SourceOutput"]
      configuration = {
        "ProjectName" = aws_codebuild_project.DASTBuildProject.name
      }
      run_order = 5
    }
  }
### Manual approval change
  stage {
    name = "Manual-Approval"

    action {
      name            = "ApprovalRequired2"
      category        = "Approval"
      owner           = "AWS"
      provider        = "Manual"
      version         = "1"
      configuration = {
        "CustomData"         = "There are no critical security vulnerabilities. Your approval is needed to deploy."
        "ExternalEntityLink" = "https://console.amazonaws.com/codesuite/codepipeline/pipelines/${var.stack_name}/general?region=${var.region}"
        "NotificationArn"    = aws_sns_topic.approval_topic.arn
      }
      run_order = 6
    }
  }

### Deploy to prod EKS
  stage {
    name = "Deploy-PRD"

    action {
      name            = "EKSDeploy"
      category        = "Build"
      owner           = "AWS"
      provider        = "CodeBuild"
      version         = "1"
      input_artifacts = ["SourceOutput"]
      configuration = {
        "ProjectName" = aws_codebuild_project.DeployBuildProject.name
      }
      run_order = 7
    }
  }

  artifact_store {
    type        = "S3"
    location    = aws_s3_bucket.CodePipelineArtifactStoreBucket.bucket
    encryption_key {
      id   = aws_kms_key.PipelineKMSKey.arn
      type = "KMS"
    }
  }

  tags = {
    "pipeline-name" = "${var.stack_name}-pipeline"
  }

#### SAST amalysis codebuild project
resource "aws_codebuild_project" "SASTBuildProject" {
  name           = "SASTBuildProject"
  description    = "Static Code Analysis Build Project"
  service_role   = aws_iam_role.StaticCodeAnalysisServiceRole.arn
  build_timeout  = 10
  queued_timeout = 10

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:4.0"
    type                        = "LINUX_CONTAINER"
    privileged_mode             = true
    image_pull_credentials_type = "CODEBUILD"

    environment_variable {
      name  = "IMAGE_REPO_NAME"
      value = var.EcrRepositoryName
    }
    # ... other environment variables ...

    # This conditional will need more context about Terraform's support for conditionals like in CloudFormation
  }

  logs_config {
    cloudwatch_logs {
      group_name  = aws_cloudwatch_log_group.example.name
      stream_name = "SASTAnalysis"
      status      = "ENABLED"
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = var.ScanWith_Anchore ? "buildspec-anchore.yml" : "buildspec-snyk.yml"
  }

  tags = {
    "pipeline-name" = "${var.stack_name}-pipeline"
  }
}

#### ECR SAST amalysis codebuild project

resource "aws_codebuild_project" "ECRSASTBuildProject" {
  name          = "ECRSASTBuildProject"
  description   = "ECR Static Code Analysis Build Project"
  service_role  = aws_iam_role.StaticCodeAnalysisServiceRole.arn
  build_timeout = 10
  queued_timeout = 10

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:4.0"
    type                        = "LINUX_CONTAINER"
    privileged_mode             = true

    environment_variable {
      name  = "IMAGE_REPO_NAME"
      value = var.EcrRepositoryName
    }
    environment_variable {
      name  = "REPOSITORY_URI"
      value = "${var.AWS_AccountId}.dkr.ecr.${var.AWS_Region}.amazonaws.com/${var.EcrRepositoryName}"
    }
    environment_variable {
      name  = "EKS_CLUSTER_NAME"
      value = var.EksClusterName
    }
    environment_variable {
      name  = "EKS_KUBECTL_ROLE_ARN"
      value = aws_iam_role.StaticCodeAnalysisServiceRole.arn
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = "buildspec-ecr.yml"
  }

  logs_config {
    cloudwatch_logs {
      group_name  = aws_cloudwatch_log_group.example.name
      stream_name = "ECRSASTAnalysis"
      status      = "ENABLED"
    }
  }

  tags = {
    "pipeline-name" = "${var.AWS_StackName}-pipeline"
  }
}

####Secrets Analysis BuildProject
resource "aws_codebuild_project" "SecBuildProject" {
  name          = "SecBuildProject"
  description   = "Secrets Analysis Build Project"
  service_role  = aws_iam_role.StaticCodeAnalysisServiceRole.arn
  build_timeout = 10
  queued_timeout = 10

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:4.0"
    type                        = "LINUX_CONTAINER"
    privileged_mode             = true

    environment_variable {
      name  = "CODECOMMIT_REPO_NAME"
      value = var.RepositoryName
    }
    environment_variable {
      name  = "REPOSITORY_URI"
      value = "${var.AWS_AccountId}.dkr.ecr.${var.AWS_Region}.amazonaws.com/${var.EcrRepositoryName}"
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = "buildspec-gitsecrets.yml"
  }

  logs_config {
    cloudwatch_logs {
      group_name  = var.CloudWatchLogGroup
      stream_name = "SecretAnalysis"
      status      = "ENABLED"
    }
  }

  tags = {
    "pipeline-name" = "${var.AWS_StackName}-pipeline"
  }
}

#### DAST analysis codebuild project
resource "aws_codebuild_project" "DASTBuildProject" {
  name          = "DASTBuildProject"
  description   = "Dynamic Code Analysis Build Project"
  service_role  = aws_iam_role.StaticCodeAnalysisServiceRole.arn
  build_timeout = 10
  queued_timeout = 10

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:4.0"
    type                        = "LINUX_CONTAINER"
    privileged_mode             = true

    environment_variable {
      name  = "OwaspZapApiKey"
      value = data.aws_ssm_parameter.SSMParameterForZapApiKey.value
    }
    environment_variable {
      name  = "OwaspZapURL"
      value = data.aws_ssm_parameter.SSMParameterOwaspZapURL.value
    }
    environment_variable {
      name  = "ApplicationURL"
      value = data.aws_ssm_parameter.SSMParameterAppURL.value
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = "buildspec-owasp-zap.yml"
  }

  logs_config {
    cloudwatch_logs {
      group_name  = var.CloudWatchLogGroup
      stream_name = "DASTAnalysis"
      status      = "ENABLED"
    }
  }

  tags = {
    "pipeline-name" = "${var.AWS_StackName}-pipeline"
  }
}

data "aws_ssm_parameter" "SSMParameterForZapApiKey" {
  name = var.SSMParameterForZapApiKeyName
}

data "aws_ssm_parameter" "SSMParameterOwaspZapURL" {
  name = var.SSMParameterOwaspZapURLName
}

data "aws_ssm_parameter" "SSMParameterAppURL" {
  name = var.SSMParameterAppURLName
}

### EKS Deploy BuildProject
resource "aws_codebuild_project" "DeployBuildProject" {
  name          = "DeployBuildProject"
  description   = "EKS Prod Deploy Build Project"
  service_role  = aws_iam_role.StaticCodeAnalysisServiceRole.arn
  build_timeout = 10
  queued_timeout = 10

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:4.0"
    type                        = "LINUX_CONTAINER"
    privileged_mode             = true

    environment_variable {
      name  = "IMAGE_REPO_NAME"
      value = var.EcrRepositoryName
    }
    environment_variable {
      name  = "REPOSITORY_URI"
      value = "${var.AWS_AccountId}.dkr.ecr.${var.AWS_Region}.amazonaws.com/${var.EcrRepositoryName}"
    }
    environment_variable {
      name  = "EKS_PROD_CLUSTER_NAME"
      value = var.EksProdClusterName
    }
    environment_variable {
      name  = "EKS_KUBECTL_ROLE_ARN"
      value = aws_iam_role.StaticCodeAnalysisServiceRole.arn
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = "buildspec-prod.yml"
  }

  logs_config {
    cloudwatch_logs {
      group_name  = var.CloudWatchLogGroup
      stream_name = "ProdDeploy"
      status      = "ENABLED"
    }
  }

  tags = {
    "pipeline-name" = "${var.AWS_StackName}-pipeline"
  }
}

###StaticCode Analysis ServiceRole
resource "aws_iam_role" "StaticCodeAnalysisServiceRole" {
  name               = "${var.AWS_StackName}-SecurityCodeAnalysisRole"
  path               = "/"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Action    = "sts:AssumeRole",
        Principal = {
          Service = "codebuild.amazonaws.com"
        }
      }
    ]
  })

  # Inline policies can be managed in Terraform with `aws_iam_role_policy`.
  inline_policy {
    name   = "SecurityCodeAnalysisPolicy"
    policy = jsonencode({
      Version   = "2012-10-17",
      Statement = [
        {
          Effect   = "Allow",
          Action   = "iam:PassRole",
          Resource = "*"
        },
        {
          Effect   = "Allow",
          Action   = [
            "iam:PassRole",
            "logs:*",
            "s3:*",
            "cloudformation:*",
            "cloudwatch:*",
            "cloudtrail:*",
            "codebuild:*",
            "codecommit:*",
            "codepipeline:*",
            "ssm:*",
            "lambda:*",
            "kms:*",
            "ecr:*",
            "eks:DescribeCluster"
          ],
          Resource = "*"
        }
      ]
    })
  }
}

# ... Your other resources and data sources should be here.

resource "aws_iam_role" "StaticCodeAnalysisServiceRole" {
  name               = "${var.AWS_StackName}-SecurityCodeAnalysisRole"
  path               = "/"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Action    = "sts:AssumeRole",
        Principal = {
          Service = "codebuild.amazonaws.com"
        }
      }
    ]
  })

  # Inline policies can be managed in Terraform with `aws_iam_role_policy`.
  inline_policy {
    name   = "SecurityCodeAnalysisPolicy"
    policy = jsonencode({
      Version   = "2012-10-17",
      Statement = [
        {
          Effect   = "Allow",
          Action   = "iam:PassRole",
          Resource = "*"
        },
        {
          Effect   = "Allow",
          Action   = [
            "iam:PassRole",
            "logs:*",
            "s3:*",
            "cloudformation:*",
            "cloudwatch:*",
            "cloudtrail:*",
            "codebuild:*",
            "codecommit:*",
            "codepipeline:*",
            "ssm:*",
            "lambda:*",
            "kms:*",
            "ecr:*",
            "eks:DescribeCluster"
          ],
          Resource = "*"
        }
      ]
    })
  }
}

#### Lambda Function Execution Role
resource "aws_iam_role" "LambdaExecutionRole" {
  name               = "${var.AWS_StackName}-LambdaExecutionRole"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })

  inline_policy {
    name   = "lambda-execution-policy"
    policy = jsonencode({
      Version   = "2012-10-17",
      Statement = [
        {
          Effect   = "Allow",
          Action   = [
            "logs:*",
            "s3:*",
            "securityhub:*"
          ],
          Resource = "*"
        }
      ]
    })
  }
}

###Pipeline Service Role
resource "aws_iam_role" "PipelineServiceRole" {
  name               = "${var.AWS_StackName}-PipelineServiceRole"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = {
          Service = "codepipeline.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })

  inline_policy {
    name   = "${var.AWS_StackName}-CodePipeline-Servicepolicy"
    policy = jsonencode({
      Version   = "2012-10-17",
      Statement = [
        {
          Effect   = "Allow",
          Action   = [
            "codecommit:CancelUploadArchive",
            "codecommit:GetBranch",
            # ... additional codecommit permissions ...
            "lambda:InvokeFunction",
            # ... additional lambda permissions ...
            "iam:PassRole",
            # ... additional permissions for other AWS services ...
          ],
          Resource = "*"
        }
      ]
    })
  }
}

# Make sure to declare AWS_StackName as a variable:
variable "AWS_StackName" {
  description = "The stack name for the AWS resources."
  type        = string
}

###Output
output "ArtifactBucketName" {
  description = "The s3 bucket name of the artifact repository with GetAtt function"
  value       = aws_s3_bucket.CodePipelineArtifactStoreBucket.arn
}

output "ArtifactBucketNameRef" {
  description = "S3 bucketname with Ref function"
  value       = aws_s3_bucket.CodePipelineArtifactStoreBucket.bucket
}

output "LambdaFunctionArn" {
  description = "LambdaFunction Arn value"
  value       = aws_lambda_function.LambdaFunSecurityHubImport.arn
}

output "CloudWatchLogGroupName" {
  description = "Cloudwatch Log group name"
  value       = aws_cloudwatch_log_group.CloudWatchLogGroup.name
}

output "PipelineKeyArn" {
  description = "KMS Key ARN for the pipeline"
  value       = aws_kms_key.PipelineKMSKey.arn
}

output "SASTBuildProjectRoleArn" {
  description = "servicerole for SAST build project"
  value       = aws_iam_role.StaticCodeAnalysisServiceRole.arn
}









 