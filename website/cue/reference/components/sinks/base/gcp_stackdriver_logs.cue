package metadata

base: components: sinks: gcp_stackdriver_logs: configuration: {
	acknowledgements: {
		description: """
			Controls how acknowledgements are handled for this sink.

			See [End-to-end Acknowledgements][e2e_acks] for more information on how Vector handles event acknowledgement.

			[e2e_acks]: https://vector.dev/docs/about/under-the-hood/architecture/end-to-end-acknowledgements/
			"""
		required: false
		type: object: options: enabled: {
			description: """
				Whether or not end-to-end acknowledgements are enabled.

				When enabled for a sink, any source connected to that sink, where the source supports
				end-to-end acknowledgements as well, will wait for events to be acknowledged by the sink
				before acknowledging them at the source.

				Enabling or disabling acknowledgements at the sink level takes precedence over any global
				[`acknowledgements`][global_acks] configuration.

				[global_acks]: https://vector.dev/docs/reference/configuration/global-options/#acknowledgements
				"""
			required: false
			type: bool: {}
		}
	}
	api_key: {
		description: """
			An API key. ([documentation](https://cloud.google.com/docs/authentication/api-keys))

			Either an API key, or a path to a service account credentials JSON file can be specified.

			If both are unset, Vector checks the `GOOGLE_APPLICATION_CREDENTIALS` environment variable for a filename. If no
			filename is named, Vector will attempt to fetch an instance service account for the compute instance the program is
			running on. If Vector is not running on a GCE instance, then you must define eith an API key or service account
			credentials JSON file.
			"""
		required: false
		type: string: {}
	}
	batch: {
		description: "Event batching behavior."
		required:    false
		type: object: options: {
			max_bytes: {
				description: """
					The maximum size of a batch that will be processed by a sink.

					This is based on the uncompressed size of the batched events, before they are
					serialized / compressed.
					"""
				required: false
				type: uint: {}
			}
			max_events: {
				description: "The maximum size of a batch, in events, before it is flushed."
				required:    false
				type: uint: {}
			}
			timeout_secs: {
				description: "The maximum age of a batch, in seconds, before it is flushed."
				required:    false
				type: float: {}
			}
		}
	}
	billing_account_id: {
		description: "The billing account ID to which to publish logs."
		required:    true
		type: string: {}
	}
	credentials_path: {
		description: """
			Path to a service account credentials JSON file. ([documentation](https://cloud.google.com/docs/authentication/production#manually))

			Either an API key, or a path to a service account credentials JSON file can be specified.

			If both are unset, Vector checks the `GOOGLE_APPLICATION_CREDENTIALS` environment variable for a filename. If no
			filename is named, Vector will attempt to fetch an instance service account for the compute instance the program is
			running on. If Vector is not running on a GCE instance, then you must define eith an API key or service account
			credentials JSON file.
			"""
		required: false
		type: string: {}
	}
	encoding: {
		description: "Transformations to prepare an event for serialization."
		required:    false
		type: object: options: {
			except_fields: {
				description: "List of fields that will be excluded from the encoded event."
				required:    false
				type: array: items: type: string: {}
			}
			metric_tag_values: {
				description: """
					Controls how metric tag values are encoded.

					When set to `single`, metric tag values will be exposed as single strings. Tags with
					multiple values will show the last assigned value, and null values will be ignored. When set
					to `full`, all metric tag values will be exposed as either null or a string value, or an
					array of null or string values.
					"""
				required: false
				type: string: {
					default: "single"
					enum: {
						full: "The full set of values of all tags will be exposed."
						single: """
															Tag values will be exposed as single strings.  Tags with multiple values will show the last
															assigned value, and null values will be ignored.
															"""
					}
				}
			}
			only_fields: {
				description: "List of fields that will be included in the encoded event."
				required:    false
				type: array: items: type: string: {}
			}
			timestamp_format: {
				description: "Format used for timestamp fields."
				required:    false
				type: string: enum: {
					rfc3339: "Represent the timestamp as a RFC 3339 timestamp."
					unix:    "Represent the timestamp as a Unix timestamp."
				}
			}
		}
	}
	folder_id: {
		description: """
			The folder ID to which to publish logs.

			See the [Google Cloud Platform folder documentation][folder_docs] for more details.

			[folder_docs]: https://cloud.google.com/resource-manager/docs/creating-managing-folders
			"""
		required: true
		type: string: {}
	}
	log_id: {
		description: """
			The log ID to which to publish logs.

			This is a name you create to identify this log stream.
			"""
		required: true
		type: string: syntax: "template"
	}
	organization_id: {
		description: """
			The organization ID to which to publish logs.

			This would be the identifier assigned to your organization on Google Cloud Platform.
			"""
		required: true
		type: string: {}
	}
	project_id: {
		description: """
			The project ID to which to publish logs.

			See the [Google Cloud Platform project management documentation][project_docs] for more details.

			[project_docs]: https://cloud.google.com/resource-manager/docs/creating-managing-projects
			"""
		required: true
		type: string: {}
	}
	request: {
		description: """
			Middleware settings for outbound requests.

			Various settings can be configured, such as concurrency and rate limits, timeouts, etc.
			"""
		required: false
		type: object: options: {
			adaptive_concurrency: {
				description: """
					Configuration of adaptive concurrency parameters.

					These parameters typically do not require changes from the default, and incorrect values can lead to meta-stable or
					unstable performance and sink behavior. Proceed with caution.
					"""
				required: false
				type: object: options: {
					decrease_ratio: {
						description: """
																The fraction of the current value to set the new concurrency limit when decreasing the limit.

																Valid values are greater than `0` and less than `1`. Smaller values cause the algorithm to scale back rapidly
																when latency increases.

																Note that the new limit is rounded down after applying this ratio.
																"""
						required: false
						type: float: default: 0.9
					}
					ewma_alpha: {
						description: """
																The weighting of new measurements compared to older measurements.

																Valid values are greater than `0` and less than `1`.

																ARC uses an exponentially weighted moving average (EWMA) of past RTT measurements as a reference to compare with
																the current RTT. Smaller values cause this reference to adjust more slowly, which may be useful if a service has
																unusually high response variability.
																"""
						required: false
						type: float: default: 0.4
					}
					rtt_deviation_scale: {
						description: """
																Scale of RTT deviations which are not considered anomalous.

																Valid values are greater than or equal to `0`, and we expect reasonable values to range from `1.0` to `3.0`.

																When calculating the past RTT average, we also compute a secondary “deviation” value that indicates how variable
																those values are. We use that deviation when comparing the past RTT average to the current measurements, so we
																can ignore increases in RTT that are within an expected range. This factor is used to scale up the deviation to
																an appropriate range.  Larger values cause the algorithm to ignore larger increases in the RTT.
																"""
						required: false
						type: float: default: 2.5
					}
				}
			}
			concurrency: {
				description: "Configuration for outbound request concurrency."
				required:    false
				type: {
					string: {
						default: "none"
						enum: {
							adaptive: """
															Concurrency will be managed by Vector's [Adaptive Request Concurrency][arc] feature.

															[arc]: https://vector.dev/docs/about/under-the-hood/networking/arc/
															"""
							none: """
															A fixed concurrency of 1.

															Only one request can be outstanding at any given time.
															"""
						}
					}
					uint: {}
				}
			}
			rate_limit_duration_secs: {
				description: "The time window, in seconds, used for the `rate_limit_num` option."
				required:    false
				type: uint: default: 1
			}
			rate_limit_num: {
				description: "The maximum number of requests allowed within the `rate_limit_duration_secs` time window."
				required:    false
				type: uint: default: 9223372036854775807
			}
			retry_attempts: {
				description: """
					The maximum number of retries to make for failed requests.

					The default, for all intents and purposes, represents an infinite number of retries.
					"""
				required: false
				type: uint: default: 9223372036854775807
			}
			retry_initial_backoff_secs: {
				description: """
					The amount of time to wait before attempting the first retry for a failed request.

					After the first retry has failed, the fibonacci sequence will be used to select future backoffs.
					"""
				required: false
				type: uint: default: 1
			}
			retry_max_duration_secs: {
				description: "The maximum amount of time, in seconds, to wait between retries."
				required:    false
				type: uint: default: 3600
			}
			timeout_secs: {
				description: """
					The maximum time a request can take before being aborted.

					It is highly recommended that you do not lower this value below the service’s internal timeout, as this could
					create orphaned requests, pile on retries, and result in duplicate data downstream.
					"""
				required: false
				type: uint: default: 60
			}
		}
	}
	resource: {
		description: "The monitored resource to associate the logs with."
		required:    true
		type: object: options: {
			"*": {
				description: """
					A templated field.

					In many cases, components can be configured in such a way where some portion of the component's functionality can be
					customized on a per-event basis. An example of this might be a sink that writes events to a file, where we want to
					provide the flexibility to specify which file an event should go to by using an event field itself as part of the
					input to the filename we use.

					By using `Template`, users can specify either fixed strings or "templated" strings, which use a common syntax to
					refer to fields in an event that will serve as the input data when rendering the template.  While a fixed string may
					look something like `my-file.log`, a template string could look something like `my-file-{{key}}.log`, and the `key`
					field of the event being processed would serve as the value when rendering the template into a string.
					"""
				required: true
				type: string: syntax: "template"
			}
			type: {
				description: """
					The monitored resource type.

					For example, the type of a Compute Engine VM instance is `gce_instance`.
					"""
				required: true
				type: string: {}
			}
		}
	}
	severity_key: {
		description: """
			The field of the log event from which to take the outgoing log’s `severity` field.

			The named field is removed from the log event if present, and must be either an integer
			between 0 and 800 or a string containing one of the [severity level names][sev_names] (case
			is ignored) or a common prefix such as `err`.

			If no severity key is specified, the severity of outgoing records is set to 0 (`DEFAULT`).

			See the [GCP Stackdriver Logging LogSeverity description][logsev_docs] for more details on
			the value of the `severity` field.

			[sev_names]: https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry#logseverity
			[logsev_docs]: https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry#logseverity
			"""
		required: false
		type: string: {}
	}
	skip_authentication: {
		description: "Skip all authentication handling. For use with integration tests only."
		required:    false
		type: bool: default: false
	}
	tls: {
		description: "TLS configuration."
		required:    false
		type: object: options: {
			alpn_protocols: {
				description: """
					Sets the list of supported ALPN protocols.

					Declare the supported ALPN protocols, which are used during negotiation with peer. Prioritized in the order
					they are defined.
					"""
				required: false
				type: array: items: type: string: examples: ["h2"]
			}
			ca_file: {
				description: """
					Absolute path to an additional CA certificate file.

					The certificate must be in the DER or PEM (X.509) format. Additionally, the certificate can be provided as an inline string in PEM format.
					"""
				required: false
				type: string: examples: ["/path/to/certificate_authority.crt"]
			}
			crt_file: {
				description: """
					Absolute path to a certificate file used to identify this server.

					The certificate must be in DER, PEM (X.509), or PKCS#12 format. Additionally, the certificate can be provided as
					an inline string in PEM format.

					If this is set, and is not a PKCS#12 archive, `key_file` must also be set.
					"""
				required: false
				type: string: examples: ["/path/to/host_certificate.crt"]
			}
			key_file: {
				description: """
					Absolute path to a private key file used to identify this server.

					The key must be in DER or PEM (PKCS#8) format. Additionally, the key can be provided as an inline string in PEM format.
					"""
				required: false
				type: string: examples: ["/path/to/host_certificate.key"]
			}
			key_pass: {
				description: """
					Passphrase used to unlock the encrypted key file.

					This has no effect unless `key_file` is set.
					"""
				required: false
				type: string: examples: ["${KEY_PASS_ENV_VAR}", "PassWord1"]
			}
			verify_certificate: {
				description: """
					Enables certificate verification.

					If enabled, certificates must be valid in terms of not being expired, as well as being issued by a trusted
					issuer. This verification operates in a hierarchical manner, checking that not only the leaf certificate (the
					certificate presented by the client/server) is valid, but also that the issuer of that certificate is valid, and
					so on until reaching a root certificate.

					Relevant for both incoming and outgoing connections.

					Do NOT set this to `false` unless you understand the risks of not verifying the validity of certificates.
					"""
				required: false
				type: bool: {}
			}
			verify_hostname: {
				description: """
					Enables hostname verification.

					If enabled, the hostname used to connect to the remote host must be present in the TLS certificate presented by
					the remote host, either as the Common Name or as an entry in the Subject Alternative Name extension.

					Only relevant for outgoing connections.

					Do NOT set this to `false` unless you understand the risks of not verifying the remote hostname.
					"""
				required: false
				type: bool: {}
			}
		}
	}
}
