//! Annotates events with pod metadata.

#![deny(missing_docs)]

use k8s_openapi::{
    api::core::v1::{Container, ContainerStatus, Pod, PodSpec, PodStatus},
    apimachinery::pkg::apis::meta::v1::ObjectMeta,
};
use kube::runtime::reflector::{store::Store, ObjectRef};
use lookup::{lookup_v2::OptionalTargetPath, owned_value_path, path, OwnedTargetPath};
use vector_config::{configurable_component, NamedComponent};
use vector_core::config::{LegacyKey, LogNamespace};

use super::{
    path_helpers::{parse_log_file_path, LogFileInfo},
    Config,
};
use crate::event::{Event, LogEvent};

/// Configuration for how the events are annotated with `Pod` metadata.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct FieldsSpec {
    /// Event field for Pod name.
    pub pod_name: OptionalTargetPath,

    /// Event field for Pod namespace.
    pub pod_namespace: OptionalTargetPath,

    /// Event field for Pod uid.
    pub pod_uid: OptionalTargetPath,

    /// Event field for Pod IPv4 address.
    pub pod_ip: OptionalTargetPath,

    /// Event field for Pod IPv4 and IPv6 addresses.
    pub pod_ips: OptionalTargetPath,

    /// Event field for Pod labels.
    pub pod_labels: OptionalTargetPath,

    /// Event field for Pod annotations.
    pub pod_annotations: OptionalTargetPath,

    /// Event field for Pod node_name.
    pub pod_node_name: OptionalTargetPath,

    /// Event field for Pod owner reference.
    pub pod_owner: OptionalTargetPath,

    /// Event field for container name.
    pub container_name: OptionalTargetPath,

    /// Event field for container ID.
    pub container_id: OptionalTargetPath,

    /// Event field for container image.
    pub container_image: OptionalTargetPath,
}

impl Default for FieldsSpec {
    fn default() -> Self {
        Self {
            pod_name: OwnedTargetPath::event(owned_value_path!("kubernetes", "pod_name")).into(),
            pod_namespace: OwnedTargetPath::event(owned_value_path!("kubernetes", "pod_namespace"))
                .into(),
            pod_uid: OwnedTargetPath::event(owned_value_path!("kubernetes", "pod_uid")).into(),
            pod_ip: OwnedTargetPath::event(owned_value_path!("kubernetes", "pod_ip")).into(),
            pod_ips: OwnedTargetPath::event(owned_value_path!("kubernetes", "pod_ips")).into(),
            pod_labels: OwnedTargetPath::event(owned_value_path!("kubernetes", "pod_labels"))
                .into(),
            pod_annotations: OwnedTargetPath::event(owned_value_path!(
                "kubernetes",
                "pod_annotations"
            ))
            .into(),
            pod_node_name: OwnedTargetPath::event(owned_value_path!("kubernetes", "pod_node_name"))
                .into(),
            pod_owner: OwnedTargetPath::event(owned_value_path!("kubernetes", "pod_owner")).into(),
            container_name: OwnedTargetPath::event(owned_value_path!(
                "kubernetes",
                "container_name"
            ))
            .into(),
            container_id: OwnedTargetPath::event(owned_value_path!("kubernetes", "container_id"))
                .into(),
            container_image: OwnedTargetPath::event(owned_value_path!(
                "kubernetes",
                "container_image"
            ))
            .into(),
        }
    }
}

/// Annotate the event with pod metadata.
pub struct PodMetadataAnnotator {
    pods_state_reader: Store<Pod>,
    fields_spec: FieldsSpec,
    log_namespace: LogNamespace,
}

impl PodMetadataAnnotator {
    /// Create a new [`PodMetadataAnnotator`].
    pub const fn new(
        pods_state_reader: Store<Pod>,
        fields_spec: FieldsSpec,
        log_namespace: LogNamespace,
    ) -> Self {
        Self {
            pods_state_reader,
            fields_spec,
            log_namespace,
        }
    }
}

impl PodMetadataAnnotator {
    /// Annotates an event with the information from the [`Pod::metadata`].
    /// The event has to be obtained from kubernetes log file, and have a
    /// [`FILE_KEY`] field set with a file that the line came from.
    pub fn annotate<'a>(&self, event: &mut Event, file: &'a str) -> Option<LogFileInfo<'a>> {
        let log = event.as_mut_log();
        let file_info = parse_log_file_path(file)?;
        let obj = ObjectRef::<Pod>::new(file_info.pod_name).within(file_info.pod_namespace);
        let resource = self.pods_state_reader.get(&obj)?;
        let pod: &Pod = resource.as_ref();

        annotate_from_file_info(log, &self.fields_spec, &file_info, self.log_namespace);
        annotate_from_metadata(log, &self.fields_spec, &pod.metadata, self.log_namespace);

        let container;
        if let Some(ref pod_spec) = pod.spec {
            annotate_from_pod_spec(log, &self.fields_spec, pod_spec, self.log_namespace);

            container = pod_spec
                .containers
                .iter()
                .find(|c| c.name == file_info.container_name);
            if let Some(container) = container {
                annotate_from_container(log, &self.fields_spec, container, self.log_namespace);
            }
        }

        if let Some(ref pod_status) = pod.status {
            annotate_from_pod_status(log, &self.fields_spec, pod_status, self.log_namespace);
            if let Some(ref container_statuses) = pod_status.container_statuses {
                let container_status = container_statuses
                    .iter()
                    .find(|c| c.name == file_info.container_name);
                if let Some(container_status) = container_status {
                    annotate_from_container_status(
                        log,
                        &self.fields_spec,
                        container_status,
                        self.log_namespace,
                    )
                }
            }
        }
        Some(file_info)
    }
}

fn annotate_from_file_info(
    log: &mut LogEvent,
    fields_spec: &FieldsSpec,
    file_info: &LogFileInfo<'_>,
    log_namespace: LogNamespace,
) {
    let legacy_key = fields_spec
        .container_name
        .path
        .as_ref()
        .map(|x| &x.path)
        .map(LegacyKey::Overwrite);

    log_namespace.insert_source_metadata(
        Config::NAME,
        log,
        legacy_key,
        path!("kubernetes", "container_name"),
        file_info.container_name.to_owned(),
    );
}

fn annotate_from_metadata(
    log: &mut LogEvent,
    fields_spec: &FieldsSpec,
    metadata: &ObjectMeta,
    log_namespace: LogNamespace,
) {
    for (legacy_key, metadata_key, value) in [
        (
            &fields_spec.pod_name,
            path!("kubernetes", "pod_name"),
            &metadata.name,
        ),
        (
            &fields_spec.pod_namespace,
            path!("kubernetes", "pod_namespace"),
            &metadata.namespace,
        ),
        (
            &fields_spec.pod_uid,
            path!("kubernetes", "pod_uid"),
            &metadata.uid,
        ),
    ]
    .iter()
    {
        if let Some(value) = value {
            let legacy_key = legacy_key
                .path
                .as_ref()
                .map(|x| &x.path)
                .map(LegacyKey::Overwrite);

            log_namespace.insert_source_metadata(
                Config::NAME,
                log,
                legacy_key,
                *metadata_key,
                value.to_owned(),
            );
        }
    }

    if let Some(owner_references) = &metadata.owner_references {
        let legacy_key = fields_spec
            .pod_owner
            .path
            .as_ref()
            .map(|x| &x.path)
            .map(LegacyKey::Overwrite);

        log_namespace.insert_source_metadata(
            Config::NAME,
            log,
            legacy_key,
            path!("kubernetes", "pod_owner"),
            format!("{}/{}", owner_references[0].kind, owner_references[0].name),
        )
    }

    if let Some(labels) = &metadata.labels {
        for (key, value) in labels.iter() {
            // TODO: Seems more efficient to move this outside of the `for` but it doesn't impl Copy.
            let legacy_key = fields_spec
                .pod_labels
                .path
                .as_ref()
                .map(|x| &x.path)
                .map(LegacyKey::Overwrite);

            log_namespace.insert_source_metadata(
                Config::NAME,
                log,
                // FIXME: This legacy_key is missing the `key` suffix.
                legacy_key,
                path!("kubernetes", "pod_labels", key),
                value.to_owned(),
            )
        }
    }

    if let Some(annotations) = &metadata.annotations {
        for (key, value) in annotations.iter() {
            // TODO: Seems more efficient to move this outside of the `for` but it doesn't impl Copy.
            let legacy_key = fields_spec
                .pod_annotations
                .path
                .as_ref()
                .map(|x| &x.path)
                .map(LegacyKey::Overwrite);

            log_namespace.insert_source_metadata(
                Config::NAME,
                log,
                // FIXME: This legacy_key is missing the `key` suffix.
                legacy_key,
                path!("kubernetes", "pod_annotations", key),
                value.to_owned(),
            )
        }
    }
}

fn annotate_from_pod_spec(
    log: &mut LogEvent,
    fields_spec: &FieldsSpec,
    pod_spec: &PodSpec,
    log_namespace: LogNamespace,
) {
    if let Some(value) = &pod_spec.node_name {
        let legacy_key = fields_spec
            .pod_node_name
            .path
            .as_ref()
            .map(|x| &x.path)
            .map(LegacyKey::Overwrite);

        log_namespace.insert_source_metadata(
            Config::NAME,
            log,
            legacy_key,
            path!("kubernetes", "pod_node_name"),
            value.to_owned(),
        )
    }
}

fn annotate_from_pod_status(
    log: &mut LogEvent,
    fields_spec: &FieldsSpec,
    pod_status: &PodStatus,
    log_namespace: LogNamespace,
) {
    if let Some(value) = &pod_status.pod_ip {
        let legacy_key = fields_spec
            .pod_ip
            .path
            .as_ref()
            .map(|x| &x.path)
            .map(LegacyKey::Overwrite);

        log_namespace.insert_source_metadata(
            Config::NAME,
            log,
            legacy_key,
            path!("kubernetes", "pod_ip"),
            value.to_owned(),
        )
    }

    if let Some(value) = &pod_status.pod_ips {
        let legacy_key = fields_spec
            .pod_ips
            .path
            .as_ref()
            .map(|x| &x.path)
            .map(LegacyKey::Overwrite);

        let value = value
            .iter()
            .filter_map(|x| x.ip.clone())
            .collect::<Vec<String>>();

        log_namespace.insert_source_metadata(
            Config::NAME,
            log,
            legacy_key,
            path!("kubernetes", "pod_ips"),
            value,
        )
    }
}

fn annotate_from_container_status(
    log: &mut LogEvent,
    fields_spec: &FieldsSpec,
    container_status: &ContainerStatus,
    log_namespace: LogNamespace,
) {
    if let Some(value) = &container_status.container_id {
        let legacy_key = fields_spec
            .container_id
            .path
            .as_ref()
            .map(|x| &x.path)
            .map(LegacyKey::Overwrite);

        log_namespace.insert_source_metadata(
            Config::NAME,
            log,
            legacy_key,
            path!("kubernetes", "container_id"),
            value.to_owned(),
        )
    }
}

fn annotate_from_container(
    log: &mut LogEvent,
    fields_spec: &FieldsSpec,
    container: &Container,
    log_namespace: LogNamespace,
) {
    if let Some(value) = &container.image {
        let legacy_key = fields_spec
            .container_image
            .path
            .as_ref()
            .map(|x| &x.path)
            .map(LegacyKey::Overwrite);

        log_namespace.insert_source_metadata(
            Config::NAME,
            log,
            legacy_key,
            path!("kubernetes", "container_image"),
            value.to_owned(),
        )
    }
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::core::v1::PodIP;
    use vector_common::assert_event_data_eq;

    use super::*;

    #[test]
    fn test_annotate_from_metadata() {
        let cases = vec![
            (
                FieldsSpec::default(),
                ObjectMeta::default(),
                LogEvent::default(),
            ),
            (
                FieldsSpec::default(),
                ObjectMeta {
                    name: Some("sandbox0-name".to_owned()),
                    namespace: Some("sandbox0-ns".to_owned()),
                    uid: Some("sandbox0-uid".to_owned()),
                    labels: Some(
                        vec![
                            ("sandbox0-label0".to_owned(), "val0".to_owned()),
                            ("sandbox0-label1".to_owned(), "val1".to_owned()),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                    annotations: Some(
                        vec![
                            ("sandbox0-annotation0".to_owned(), "val0".to_owned()),
                            ("sandbox0-annotation1".to_owned(), "val1".to_owned()),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                    ..ObjectMeta::default()
                },
                {
                    let mut log = LogEvent::default();
                    log.insert("kubernetes.pod_name", "sandbox0-name");
                    log.insert("kubernetes.pod_namespace", "sandbox0-ns");
                    log.insert("kubernetes.pod_uid", "sandbox0-uid");
                    log.insert("kubernetes.pod_labels.\"sandbox0-label0\"", "val0");
                    log.insert("kubernetes.pod_labels.\"sandbox0-label1\"", "val1");
                    log.insert(
                        "kubernetes.pod_annotations.\"sandbox0-annotation0\"",
                        "val0",
                    );
                    log.insert(
                        "kubernetes.pod_annotations.\"sandbox0-annotation1\"",
                        "val1",
                    );
                    log
                },
            ),
            (
                FieldsSpec {
                    pod_name: OwnedTargetPath::event(owned_value_path!("name")).into(),
                    pod_namespace: OwnedTargetPath::event(owned_value_path!("ns")).into(),
                    pod_uid: OwnedTargetPath::event(owned_value_path!("uid")).into(),
                    pod_labels: OwnedTargetPath::event(owned_value_path!("labels")).into(),
                    // ensure we can disable fields
                    pod_annotations: OptionalTargetPath::none(),
                    ..Default::default()
                },
                ObjectMeta {
                    name: Some("sandbox0-name".to_owned()),
                    namespace: Some("sandbox0-ns".to_owned()),
                    uid: Some("sandbox0-uid".to_owned()),
                    labels: Some(
                        vec![
                            ("sandbox0-label0".to_owned(), "val0".to_owned()),
                            ("sandbox0-label1".to_owned(), "val1".to_owned()),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                    annotations: Some(
                        vec![
                            ("sandbox0-annotation0".to_owned(), "val0".to_owned()),
                            ("sandbox0-annotation1".to_owned(), "val1".to_owned()),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                    ..ObjectMeta::default()
                },
                {
                    let mut log = LogEvent::default();
                    log.insert("name", "sandbox0-name");
                    log.insert("ns", "sandbox0-ns");
                    log.insert("uid", "sandbox0-uid");
                    log.insert("labels.\"sandbox0-label0\"", "val0");
                    log.insert("labels.\"sandbox0-label1\"", "val1");
                    log
                },
            ),
            // Ensure we properly handle labels with `.` as flat fields.
            (
                FieldsSpec::default(),
                ObjectMeta {
                    name: Some("sandbox0-name".to_owned()),
                    namespace: Some("sandbox0-ns".to_owned()),
                    uid: Some("sandbox0-uid".to_owned()),
                    labels: Some(
                        vec![
                            ("nested0.label0".to_owned(), "val0".to_owned()),
                            ("nested0.label1".to_owned(), "val1".to_owned()),
                            ("nested1.label0".to_owned(), "val2".to_owned()),
                            ("nested2.label0.deep0".to_owned(), "val3".to_owned()),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                    ..ObjectMeta::default()
                },
                {
                    let mut log = LogEvent::default();
                    log.insert("kubernetes.pod_name", "sandbox0-name");
                    log.insert("kubernetes.pod_namespace", "sandbox0-ns");
                    log.insert("kubernetes.pod_uid", "sandbox0-uid");
                    log.insert(r#"kubernetes.pod_labels."nested0.label0""#, "val0");
                    log.insert(r#"kubernetes.pod_labels."nested0.label1""#, "val1");
                    log.insert(r#"kubernetes.pod_labels."nested1.label0""#, "val2");
                    log.insert(r#"kubernetes.pod_labels."nested2.label0.deep0""#, "val3");
                    log
                },
            ),
        ];

        for (fields_spec, metadata, expected) in cases.into_iter() {
            let mut log = LogEvent::default();
            annotate_from_metadata(&mut log, &fields_spec, &metadata, LogNamespace::Legacy);
            assert_event_data_eq!(log, expected);
        }
    }

    #[test]
    fn test_annotate_from_file_info() {
        let cases = vec![(
            FieldsSpec::default(),
            "/var/log/pods/sandbox0-ns_sandbox0-name_sandbox0-uid/sandbox0-container0-name/1.log",
            {
                let mut log = LogEvent::default();
                log.insert("kubernetes.container_name", "sandbox0-container0-name");
                log
            },
        ),(
            FieldsSpec{
                container_name: OwnedTargetPath::event(owned_value_path!("container_name")).into(),
                ..Default::default()
            },
            "/var/log/pods/sandbox0-ns_sandbox0-name_sandbox0-uid/sandbox0-container0-name/1.log",
            {
                let mut log = LogEvent::default();
                log.insert("container_name", "sandbox0-container0-name");
                log
            },
        )];

        for (fields_spec, file, expected) in cases.into_iter() {
            let mut log = LogEvent::default();
            let file_info = parse_log_file_path(file).unwrap();
            annotate_from_file_info(&mut log, &fields_spec, &file_info, LogNamespace::Legacy);
            assert_event_data_eq!(log, expected);
        }
    }

    #[test]
    fn test_annotate_from_pod_spec() {
        let cases = vec![
            (
                FieldsSpec::default(),
                PodSpec::default(),
                LogEvent::default(),
            ),
            (
                FieldsSpec::default(),
                PodSpec {
                    node_name: Some("sandbox0-node-name".to_owned()),
                    ..Default::default()
                },
                {
                    let mut log = LogEvent::default();
                    log.insert("kubernetes.pod_node_name", "sandbox0-node-name");
                    log
                },
            ),
            (
                FieldsSpec {
                    pod_node_name: OwnedTargetPath::event(owned_value_path!("node_name")).into(),
                    ..Default::default()
                },
                PodSpec {
                    node_name: Some("sandbox0-node-name".to_owned()),
                    ..Default::default()
                },
                {
                    let mut log = LogEvent::default();
                    log.insert("node_name", "sandbox0-node-name");
                    log
                },
            ),
        ];

        for (fields_spec, pod_spec, expected) in cases.into_iter() {
            let mut log = LogEvent::default();
            annotate_from_pod_spec(&mut log, &fields_spec, &pod_spec, LogNamespace::Legacy);
            assert_event_data_eq!(log, expected);
        }
    }

    #[test]
    fn test_annotate_from_pod_status() {
        let cases = vec![
            (
                FieldsSpec::default(),
                PodStatus::default(),
                LogEvent::default(),
            ),
            (
                FieldsSpec::default(),
                PodStatus {
                    pod_ip: Some("192.168.1.2".to_owned()),
                    ..Default::default()
                },
                {
                    let mut log = LogEvent::default();
                    log.insert("kubernetes.pod_ip", "192.168.1.2");
                    log
                },
            ),
            (
                FieldsSpec::default(),
                PodStatus {
                    pod_ips: Some(vec![PodIP {
                        ip: Some("192.168.1.2".to_owned()),
                    }]),
                    ..Default::default()
                },
                {
                    let mut log = LogEvent::default();
                    let ips_vec = vec!["192.168.1.2"];
                    log.insert("kubernetes.pod_ips", ips_vec);
                    log
                },
            ),
            (
                FieldsSpec {
                    pod_ip: OwnedTargetPath::event(owned_value_path!(
                        "kubernetes",
                        "custom_pod_ip"
                    ))
                    .into(),
                    pod_ips: OwnedTargetPath::event(owned_value_path!(
                        "kubernetes",
                        "custom_pod_ips"
                    ))
                    .into(),
                    ..FieldsSpec::default()
                },
                PodStatus {
                    pod_ip: Some("192.168.1.2".to_owned()),
                    pod_ips: Some(vec![
                        PodIP {
                            ip: Some("192.168.1.2".to_owned()),
                        },
                        PodIP {
                            ip: Some("192.168.1.3".to_owned()),
                        },
                    ]),
                    ..Default::default()
                },
                {
                    let mut log = LogEvent::default();
                    log.insert("kubernetes.custom_pod_ip", "192.168.1.2");
                    let ips_vec = vec!["192.168.1.2", "192.168.1.3"];
                    log.insert("kubernetes.custom_pod_ips", ips_vec);
                    log
                },
            ),
            (
                FieldsSpec {
                    pod_node_name: OwnedTargetPath::event(owned_value_path!("node_name")).into(),
                    ..FieldsSpec::default()
                },
                PodStatus {
                    pod_ip: Some("192.168.1.2".to_owned()),
                    pod_ips: Some(vec![
                        PodIP {
                            ip: Some("192.168.1.2".to_owned()),
                        },
                        PodIP {
                            ip: Some("192.168.1.3".to_owned()),
                        },
                    ]),
                    ..Default::default()
                },
                {
                    let mut log = LogEvent::default();
                    log.insert("kubernetes.pod_ip", "192.168.1.2");
                    let ips_vec = vec!["192.168.1.2", "192.168.1.3"];
                    log.insert("kubernetes.pod_ips", ips_vec);
                    log
                },
            ),
        ];

        for (fields_spec, pod_status, expected) in cases.into_iter() {
            let mut log = LogEvent::default();
            annotate_from_pod_status(&mut log, &fields_spec, &pod_status, LogNamespace::Legacy);
            assert_event_data_eq!(log, expected);
        }
    }

    #[test]
    fn test_annotate_from_container_status() {
        let cases = vec![
            (
                FieldsSpec::default(),
                ContainerStatus::default(),
                LogEvent::default(),
            ),
            (
                FieldsSpec {
                    ..FieldsSpec::default()
                },
                ContainerStatus {
                    container_id: Some("container_id_foo".to_owned()),
                    ..ContainerStatus::default()
                },
                {
                    let mut log = LogEvent::default();
                    log.insert("kubernetes.container_id", "container_id_foo");
                    log
                },
            ),
        ];
        for (fields_spec, container_status, expected) in cases.into_iter() {
            let mut log = LogEvent::default();
            annotate_from_container_status(
                &mut log,
                &fields_spec,
                &container_status,
                LogNamespace::Legacy,
            );
            assert_event_data_eq!(log, expected);
        }
    }

    #[test]
    fn test_annotate_from_container() {
        let cases = vec![
            (
                FieldsSpec::default(),
                Container::default(),
                LogEvent::default(),
            ),
            (
                FieldsSpec::default(),
                Container {
                    image: Some("sandbox0-container-image".to_owned()),
                    ..Default::default()
                },
                {
                    let mut log = LogEvent::default();
                    log.insert("kubernetes.container_image", "sandbox0-container-image");
                    log
                },
            ),
            (
                FieldsSpec {
                    container_image: OwnedTargetPath::event(owned_value_path!("container_image"))
                        .into(),
                    ..Default::default()
                },
                Container {
                    image: Some("sandbox0-container-image".to_owned()),
                    ..Default::default()
                },
                {
                    let mut log = LogEvent::default();
                    log.insert("container_image", "sandbox0-container-image");
                    log
                },
            ),
        ];

        for (fields_spec, container, expected) in cases.into_iter() {
            let mut log = LogEvent::default();
            annotate_from_container(&mut log, &fields_spec, &container, LogNamespace::Legacy);
            assert_event_data_eq!(log, expected);
        }
    }
}
