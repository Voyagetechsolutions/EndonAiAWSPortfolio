"""Secure static hosting for the Endon AI portfolio site.

Hosts the site the way a security engineer should host anything public-facing:

* the S3 origin bucket is **private** — no public access, no website endpoint;
* CloudFront reaches it through Origin Access Control (OAC), so the bucket is only
  readable via the distribution;
* HTTPS is enforced (viewers are redirected to TLS);
* a response-headers policy adds HSTS, nosniff, frame-deny, a referrer policy and a
  Content-Security-Policy that allows only Google Fonts as an external origin;
* an optional custom domain (endonai.com) is served with an ACM certificate.

Deploy with `python build.py` first, then `cdk deploy` from this folder.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aws_cdk import CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import aws_cloudfront_origins as origins
from aws_cdk import aws_route53 as route53
from aws_cdk import aws_route53_targets as route53_targets
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_deployment as s3deploy
from constructs import Construct

SITE_ROOT = Path(__file__).resolve().parents[1]
DIST = SITE_ROOT / "dist"

# Only self, inline styles, and Google Fonts. No third-party scripts.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; "
    "script-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "base-uri 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'"
)


class PortfolioSiteStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        domain: str | None = None,
        hosted_zone_id: str | None = None,
        certificate_arn: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        bucket = s3.Bucket(
            self,
            "SiteBucket",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        headers = cloudfront.ResponseHeadersPolicy(
            self,
            "SecurityHeaders",
            security_headers_behavior=cloudfront.ResponseSecurityHeadersBehavior(
                strict_transport_security=cloudfront.ResponseHeadersStrictTransportSecurity(
                    access_control_max_age=Duration.days(730),
                    include_subdomains=True,
                    override=True,
                ),
                content_type_options=cloudfront.ResponseHeadersContentTypeOptions(override=True),
                frame_options=cloudfront.ResponseHeadersFrameOptions(
                    frame_option=cloudfront.HeadersFrameOption.DENY, override=True
                ),
                referrer_policy=cloudfront.ResponseHeadersReferrerPolicy(
                    referrer_policy=cloudfront.HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
                    override=True,
                ),
                content_security_policy=cloudfront.ResponseHeadersContentSecurityPolicy(
                    content_security_policy=CONTENT_SECURITY_POLICY, override=True
                ),
            ),
        )

        certificate = None
        domain_names = None
        if domain and certificate_arn:
            certificate = acm.Certificate.from_certificate_arn(self, "Cert", certificate_arn)
            domain_names = [domain]

        distribution = cloudfront.Distribution(
            self,
            "SiteDistribution",
            default_root_object="index.html",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(bucket),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                response_headers_policy=headers,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
            ),
            domain_names=domain_names,
            certificate=certificate,
            minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
            price_class=cloudfront.PriceClass.PRICE_CLASS_100,
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=403, response_http_status=200, response_page_path="/index.html"
                )
            ],
        )

        if DIST.exists():
            s3deploy.BucketDeployment(
                self,
                "DeploySite",
                sources=[s3deploy.Source.asset(str(DIST))],
                destination_bucket=bucket,
                distribution=distribution,
                distribution_paths=["/*"],
            )

        if domain and hosted_zone_id:
            zone = route53.HostedZone.from_hosted_zone_attributes(
                self, "Zone", hosted_zone_id=hosted_zone_id, zone_name=domain
            )
            route53.ARecord(
                self,
                "AliasRecord",
                zone=zone,
                target=route53.RecordTarget.from_alias(
                    route53_targets.CloudFrontTarget(distribution)
                ),
            )

        CfnOutput(self, "DistributionDomain", value=distribution.distribution_domain_name)
        if domain:
            CfnOutput(self, "SiteUrl", value=f"https://{domain}")
