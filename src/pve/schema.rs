//! Proxmox's own parameter schema for creating a guest.
//!
//! PVE defines its entire API in JSON Schema — that is how it generates its
//! documentation and validates every call — and ships the result on each node
//! at `/usr/share/pve-docs/api-viewer/apidoc.js`. Reading it here means the
//! panel can validate a hardware profile, and build a form for one, against the
//! rules *this* node will actually enforce, rather than against whatever PVE
//! release the panel was written for. It is also the only way to get the enums:
//! nobody should be hand-maintaining the list of valid `scsihw` values.
//!
//! The file is JavaScript only in the sense that it assigns a JSON array to a
//! variable, so the array is sliced out rather than parsed as a program. That
//! is deliberately tolerant of the assignment changing shape (`const` to `var`,
//! a different variable name) because none of it is contractual.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};

/// The API path whose POST parameters describe creating a guest.
const QEMU_CREATE_PATH: &str = "/nodes/{node}/qemu";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QemuCreateSchema {
    /// Every accepted parameter, keyed by name, with PVE's own type, enum,
    /// pattern, default and description left exactly as it wrote them.
    pub parameters: BTreeMap<String, Value>,
}

pub fn load(apidoc_path: &str) -> Result<QemuCreateSchema> {
    let raw = std::fs::read_to_string(apidoc_path)
        .map_err(|error| Error::Schema(format!("could not read {apidoc_path}: {error}")))?;

    parse(&raw)
}

pub fn parse(raw: &str) -> Result<QemuCreateSchema> {
    let start = raw
        .find('[')
        .ok_or_else(|| Error::Schema("no JSON array in the API documentation".to_owned()))?;
    let end = raw
        .rfind(']')
        .ok_or_else(|| Error::Schema("no JSON array in the API documentation".to_owned()))?;

    if end <= start {
        return Err(Error::Schema(
            "the API documentation is not a JSON array".to_owned(),
        ));
    }

    let tree: Value = serde_json::from_str(&raw[start..=end])
        .map_err(|error| Error::Schema(format!("malformed API documentation: {error}")))?;

    let node = find(&tree, QEMU_CREATE_PATH).ok_or_else(|| {
        Error::Schema(format!(
            "{QEMU_CREATE_PATH} is missing from the API documentation"
        ))
    })?;

    let properties = node
        .get("info")
        .and_then(|info| info.get("POST"))
        .and_then(|post| post.get("parameters"))
        .and_then(|parameters| parameters.get("properties"))
        .and_then(Value::as_object)
        .ok_or_else(|| Error::Schema(format!("{QEMU_CREATE_PATH} declares no POST parameters")))?;

    Ok(QemuCreateSchema {
        parameters: properties
            .iter()
            .map(|(name, schema)| (name.clone(), schema.clone()))
            .collect(),
    })
}

/// Depth-first search for the tree node at `path`.
///
/// The document is an array of nodes, each of which may carry its own
/// `children` array, so recursion is over both shapes rather than one.
fn find<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    match value {
        Value::Array(nodes) => nodes.iter().find_map(|node| find(node, path)),
        Value::Object(node) => {
            if node.get("path").and_then(Value::as_str) == Some(path) {
                return Some(value);
            }

            node.get("children")
                .and_then(|children| find(children, path))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shaped like the real file: a variable assignment around a nested tree,
    /// with the guest-create parameters several levels down.
    const APIDOC: &str = r#"
        const pveapi = [
           {
              "children" : [
                 {
                    "children" : [
                       {
                          "info" : {
                             "POST" : {
                                "parameters" : {
                                   "properties" : {
                                      "scsihw" : {
                                         "description" : "SCSI controller model",
                                         "enum" : ["lsi", "virtio-scsi-single"],
                                         "optional" : 1,
                                         "type" : "string"
                                      },
                                      "vmid" : { "type" : "integer" }
                                   }
                                }
                             }
                          },
                          "path" : "/nodes/{node}/qemu",
                          "text" : "qemu"
                       }
                    ],
                    "path" : "/nodes/{node}",
                    "text" : "{node}"
                 }
              ],
              "path" : "/nodes",
              "text" : "nodes"
           }
        ];
    "#;

    #[test]
    fn extracts_the_guest_create_parameters() {
        let schema = parse(APIDOC).expect("parses");

        assert_eq!(schema.parameters.len(), 2);
        assert_eq!(
            schema.parameters["scsihw"]["enum"][1].as_str(),
            Some("virtio-scsi-single")
        );
    }

    /// PVE's descriptions and enums are the whole point of reading the file, so
    /// they must survive verbatim rather than being narrowed to a type name.
    #[test]
    fn keeps_proxmoxs_own_metadata() {
        let schema = parse(APIDOC).expect("parses");

        assert_eq!(
            schema.parameters["scsihw"]["description"].as_str(),
            Some("SCSI controller model")
        );
        assert_eq!(schema.parameters["scsihw"]["optional"].as_i64(), Some(1));
    }

    #[test]
    fn rejects_a_document_without_the_endpoint() {
        let error = parse("const pveapi = [{\"path\": \"/access\"}];").expect_err("no endpoint");

        assert!(matches!(error, Error::Schema(_)));
    }

    #[test]
    fn rejects_a_file_that_is_not_json() {
        assert!(matches!(parse("not javascript"), Err(Error::Schema(_))));
    }
}
