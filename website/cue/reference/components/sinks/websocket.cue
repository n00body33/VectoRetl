package metadata

components: sinks: websocket: {
	title: "WebSocket"

	classes: {
		commonly_used: false
		delivery:      "best_effort"
		development:   "beta"
		egress_method: "stream"
		service_providers: []
		stateful: false
	}

	features: {
		acknowledgements: true
		auto_generated:   true
		healthcheck: enabled: true
		send: {
			compression: enabled: false
			encoding: {
				enabled: true
				codec: {
					enabled: true
					enum: ["json", "text"]
				}
			}
			request: enabled: false
			tls: {
				enabled:                true
				can_verify_certificate: true
				can_verify_hostname:    true
				enabled_default:        false
				enabled_by_scheme:      true
			}
			to: {
				service: services.websocket
				interface: {
					socket: {
						direction: "outgoing"
						protocols: ["tcp"]
						ssl: "optional"
					}
				}
			}
		}
	}

	support: {
		targets: {
			"aarch64-unknown-linux-gnu":      true
			"aarch64-unknown-linux-musl":     true
			"armv7-unknown-linux-gnueabihf":  true
			"armv7-unknown-linux-musleabihf": true
			"x86_64-apple-darwin":            true
			"x86_64-pc-windows-msv":          true
			"x86_64-unknown-linux-gnu":       true
			"x86_64-unknown-linux-musl":      true
		}
		requirements: []
		warnings: []
		notices: []
	}

	configuration: base.components.sinks.websocket.configuration & {
		ping_timeout: warnings: ["This option is ignored if the `ping_interval` option is not set."]
    }

	input: {
		logs:    true
		metrics: null
		traces:  false
	}

	telemetry: metrics: {
		open_connections:                 components.sources.internal_metrics.output.metrics.open_connections
		connection_established_total:     components.sources.internal_metrics.output.metrics.connection_established_total
		connection_failed_total:          components.sources.internal_metrics.output.metrics.connection_failed_total
		connection_shutdown_total:        components.sources.internal_metrics.output.metrics.connection_shutdown_total
		connection_errors_total:          components.sources.internal_metrics.output.metrics.connection_errors_total
		events_in_total:                  components.sources.internal_metrics.output.metrics.events_in_total
		events_out_total:                 components.sources.internal_metrics.output.metrics.events_out_total
		component_sent_bytes_total:       components.sources.internal_metrics.output.metrics.component_sent_bytes_total
		component_sent_events_total:      components.sources.internal_metrics.output.metrics.component_sent_events_total
		events_out_total:                 components.sources.internal_metrics.output.metrics.events_out_total
		component_sent_event_bytes_total: components.sources.internal_metrics.output.metrics.component_sent_event_bytes_total
	}
}
