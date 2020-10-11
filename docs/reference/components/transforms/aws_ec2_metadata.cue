package metadata

components: transforms: aws_ec2_metadata: {
	title:             "AWS EC2 Metadata"
	short_description: "Accepts log events and allows you to enrich logs with AWS EC2 instance metadata."
	long_description:  "Accepts log events and allows you to enrich logs with AWS EC2 instance metadata."

	classes: {
		commonly_used: false
		egress_method: "stream"
		function:      "enrich"
	}

	features: {}

	statuses: {
		development: "beta"
	}

	support: {

		platforms: {
			"aarch64-unknown-linux-gnu":  true
			"aarch64-unknown-linux-musl": true
			"x86_64-apple-darwin":        true
			"x86_64-pc-windows-msv":      true
			"x86_64-unknown-linux-gnu":   true
			"x86_64-unknown-linux-musl":  true
		}

		requirements: [
			#"""
				[AWS IMDS v2][urls.aws_ec2_instance_metadata] is required for
				security reasons. This is available by default on all EC2
				instances.
				"""#,
			#"""
				Running this transform within Docker on EC2 requires 2 network
				hops. Users must raise this limit by running the following
				command:

				```bash
				aws ec2 modify-instance-metadata-options --instance-id <ID> --http-endpoint enabled --http-put-response-hop-limit 2
				```
				"""#,
		]
		warnings: []
		notices: []
	}

	configuration: {
		fields: {
			common:      true
			description: "A list of fields to include in each event."
			required:    false
			warnings: []
			type: array: {
				default: ["instance-id", "local-hostname", "local-ipv4", "public-hostname", "public-ipv4", "ami-id", "availability-zone", "vpc-id", "subnet-id", "region"]
				items: type: string: examples: ["instance-id", "local-hostname"]
			}
		}
		namespace: {
			common:      true
			description: "Prepend a namespace to each field's key."
			required:    false
			warnings: []
			type: string: {
				default: ""
				examples: ["", "ec2", "aws.ec2"]
			}
		}
		refresh_interval_secs: {
			common:      true
			description: "The interval in seconds at which the EC2 Metadata api will be called."
			required:    false
			warnings: []
			type: uint: {
				default: 10
				unit:    null
			}
		}
	}

	input: {
		logs:    true
		metrics: false
	}
}
