import pulumi
import pulumi_aws_native as aws_native
import pulumi_aws as aws
import json
import os
import re


# defining config file
with open("./config.json") as config_file:
    data = json.load(config_file)

# defining userdata file
with open("userdata.sh", "r") as file:
    user_data_script = file.read()

# decalaring env variables
STACK_NAME = data["STACK_NAME"]
PRIVATE_SUBNET_IDS = data["PRIVATE_SUBNET_IDS"]
VPC_ID = data["VPC_ID"]
INSTANCE_TYPE = data["INSTANCE_TYPE"]
CLOUDWATCH_LOGS = data["CLOUDWATCH_LOGS"]
AMI = data["AMI"]
DOMAIN = data["DOMAIN"]
APPLICATION_DOMAIN = data["APPLICATION_DOMAIN"]
POLICY_REF_NAME = data["POLICY_REF_NAME"]
EMAIL_DOMAIN = data["EMAIL_DOMAIN"]
GROUP_ID = data["GROUP_ID"]
HTTPS_PORT = data["HTTPS_PORT"]
HTTP_PORT = data["HTTP_PORT"]
PROTOCOL = data["PROTOCOL"]

# getting acm cert
ssl_cert = aws.acm.get_certificate(domain=DOMAIN, statuses=["ISSUED"])

# cedar policy
cedar_policy = """
        permit(principal, action, resource)
        when {
            context.{POLICY_REF_NAME}.groups has "{GROUP_ID}" &&
            context.{POLICY_REF_NAME}.user.email.address like "*@{EMAIL_DOMAIN}" &&
            context.{POLICY_REF_NAME}.user.email.verified == true
        };
        """
cedar_policy_env_vars = {
    "{POLICY_REF_NAME}": POLICY_REF_NAME,
    "{GROUP_ID}": GROUP_ID,
    "{EMAIL_DOMAIN}": EMAIL_DOMAIN,
}

for env_var, var_name in cedar_policy_env_vars.items():
    var_value = var_name
    if var_value:
        cedar_policy = re.sub(re.escape(env_var), var_value, cedar_policy)


# function to create a stack for ec2
def ec2_stack():

    # creating a security group for ec2 instance
    ec2_sg = aws.ec2.SecurityGroup(
        f"{STACK_NAME}-ec2-sg",
        vpc_id=VPC_ID,
        ingress=[
            aws.ec2.SecurityGroupIngressArgs(
                from_port=HTTP_PORT,
                to_port=HTTP_PORT,
                protocol=PROTOCOL,
                cidr_blocks=["0.0.0.0/0"],
            )
        ],
        egress=[
            aws.ec2.SecurityGroupEgressArgs(
                from_port=0,
                to_port=0,
                protocol="-1",
                cidr_blocks=["0.0.0.0/0"],
            )
        ],
        tags={
            "Name": f"{STACK_NAME}-ec2-sg",
        },
    )

    # creating a sample ec2 instance which wil be fronted by alb
    ec2_instance = aws.ec2.Instance(
        f"{STACK_NAME}-ec2",
        instance_type=INSTANCE_TYPE,
        subnet_id=PRIVATE_SUBNET_IDS[0],
        vpc_security_group_ids=[ec2_sg.id],
        ami=AMI,
        user_data=user_data_script,
        tags={
            "Name": f"{STACK_NAME}-ec2",
        },
    )
    return (ec2_sg, ec2_instance)


# function to create a stack for alb
def alb_stack(ec2_sg_id, ec2_instance_id):

    # creating a security group for alb instance
    alb_sg = aws.ec2.SecurityGroup(
        f"{STACK_NAME}-alb-sg",
        vpc_id=VPC_ID,
        ingress=[
            aws.ec2.SecurityGroupIngressArgs(
                from_port=HTTPS_PORT,
                to_port=HTTPS_PORT,
                protocol=PROTOCOL,
                cidr_blocks=["0.0.0.0/0"],
            )
        ],
        egress=[
            aws.ec2.SecurityGroupEgressArgs(
                from_port=0,
                to_port=0,
                protocol="-1",
                cidr_blocks=["0.0.0.0/0"],
            )
        ],
        tags={
            "Name": f"{STACK_NAME}-alb-sg",
        },
    )

    ec2_sg_rule = aws.ec2.SecurityGroupRule(
        f"{STACK_NAME}-ec2-sg-rule",
        type="ingress",
        from_port=HTTP_PORT,
        to_port=HTTP_PORT,
        protocol=PROTOCOL,
        source_security_group_id=alb_sg,
        security_group_id=ec2_sg_id,
    )

    # creating an internal ALB
    load_balancer = aws.alb.LoadBalancer(
        f"{STACK_NAME}-alb",
        name=f"{STACK_NAME}-alb",
        internal=True,
        load_balancer_type="application",
        security_groups=[alb_sg.id],
        subnets=PRIVATE_SUBNET_IDS,
        tags={
            "Name": f"{STACK_NAME}-alb",
        },
    )

    # creating a target group with target type 'instance'
    target_group = aws.alb.TargetGroup(
        f"{STACK_NAME}-tg",
        port=HTTP_PORT,
        protocol="HTTP",
        target_type="instance",
        vpc_id=VPC_ID,
        tags={
            "Name": f"{STACK_NAME}-tg",
        },
    )

    # attaching the EC2 instance to the target group
    target_group_attachment = aws.alb.TargetGroupAttachment(
        f"{STACK_NAME}-tg-attachment",
        target_group_arn=target_group.arn,
        target_id=ec2_instance_id,
        port=HTTP_PORT,
    )
    # creating a listener
    listener = aws.alb.Listener(
        f"{STACK_NAME}-listener",
        load_balancer_arn=load_balancer.arn,
        port=HTTPS_PORT,
        protocol="HTTPS",
        ssl_policy="ELBSecurityPolicy-TLS13-1-2-2021-06",
        certificate_arn=ssl_cert.arn,
        default_actions=[
            {
                "type": "forward",
                "target_group_arn": target_group.arn,
            }
        ],
    )
    return load_balancer


# function to create a stack for voc verified access
def vpc_verified_access(load_balancer_arn):
    # creating a security group for vpc verified access
    vpc_verified_access_sg = aws.ec2.SecurityGroup(
        f"{STACK_NAME}-sg",
        vpc_id=VPC_ID,
        ingress=[
            aws.ec2.SecurityGroupIngressArgs(
                from_port=HTTPS_PORT,
                to_port=HTTPS_PORT,
                protocol=PROTOCOL,
                cidr_blocks=["0.0.0.0/0"],
            )
        ],
        egress=[
            aws.ec2.SecurityGroupEgressArgs(
                from_port=0,
                to_port=0,
                protocol="-1",
                cidr_blocks=["0.0.0.0/0"],
            )
        ],
        tags={
            "Name": f"{STACK_NAME}-sg",
        },
    )
    # creating a cloudwatch log group for vvpc verified access
    cloudwatch_log_group = aws.cloudwatch.LogGroup(
        f"{STACK_NAME}-log-group",
        tags={
            "Name": f"{STACK_NAME}-log-group",
        },
    )

    # creating vpc verified access stack
    trust_provider = aws_native.ec2.VerifiedAccessTrustProvider(
        f"{STACK_NAME}-trust-provider",
        policy_reference_name=POLICY_REF_NAME,
        trust_provider_type="user",
        user_trust_provider_type="iam-identity-center",
        tags=[
            aws_native.ec2.VerifiedAccessTrustProviderTagArgs(
                key="Name",
                value=f"{STACK_NAME}-trust-provider",
            )
        ],
    )
    verified_access_instance = aws_native.ec2.VerifiedAccessInstance(
        f"{STACK_NAME}-instance",
        verified_access_trust_provider_ids=[trust_provider],
        logging_configurations=aws_native.ec2.VerifiedAccessInstanceVerifiedAccessLogsArgs(
            cloud_watch_logs=aws_native.ec2.VerifiedAccessInstanceVerifiedAccessLogsCloudWatchLogsPropertiesArgs(
                enabled=CLOUDWATCH_LOGS, log_group=cloudwatch_log_group
            )
        ),
        tags=[
            aws_native.ec2.VerifiedAccessInstanceTagArgs(
                key="Name",
                value=f"{STACK_NAME}-instance",
            )
        ],
    )
    verified_access_group = aws_native.ec2.VerifiedAccessGroup(
        f"{STACK_NAME}-group",
        verified_access_instance_id=verified_access_instance,
        policy_document=cedar_policy,
        tags=[
            aws_native.ec2.VerifiedAccessGroupTagArgs(
                key="Name",
                value=f"{STACK_NAME}-group",
            )
        ],
    )
    verified_access_endpoint = aws_native.ec2.VerifiedAccessEndpoint(
        f"{STACK_NAME}-endpoint",
        application_domain=APPLICATION_DOMAIN,
        domain_certificate_arn=ssl_cert.arn,
        endpoint_domain_prefix=STACK_NAME,
        verified_access_group_id=verified_access_group,
        attachment_type="vpc",
        endpoint_type="load-balancer",
        security_group_ids=[vpc_verified_access_sg],
        load_balancer_options=aws_native.ec2.VerifiedAccessEndpointLoadBalancerOptionsArgs(
            load_balancer_arn=load_balancer_arn,
            port=HTTPS_PORT,
            protocol="https",
            subnet_ids=PRIVATE_SUBNET_IDS,
        ),
        tags=[
            aws_native.ec2.VerifiedAccessEndpointTagArgs(
                key="Name",
                value=f"{STACK_NAME}-endpoint",
            )
        ],
    )


ec2 = ec2_stack()
alb = alb_stack(ec2[0], ec2[1])
vpc_verified_access(alb.arn)
