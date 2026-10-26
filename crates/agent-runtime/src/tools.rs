//! Trusted host tool catalog. Task parameters never add tools or grants.
use agent_core::digest_json;
use rig::{completion::ToolDefinition, message::ToolName};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{RuntimeError, ToolRevision, pending_metadata_has_credential};

pub use agent_core::TOOL_REGISTRY_FORMAT;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegisteredTool {
    pub name: String,
    pub revision: String,
    pub description: String,
    pub parameters: Value,
    pub scope: String,
    #[serde(default)]
    pub artifact_output: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(transparent)]
pub struct ToolRegistry(Vec<RegisteredTool>);

impl ToolRegistry {
    pub fn new(mut tools: Vec<RegisteredTool>) -> Result<Self, RuntimeError> {
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        if tools.is_empty() || tools.len() > 64 {
            return Err(RuntimeError::Format("tool registry size refused".into()));
        }
        for (index, tool) in tools.iter().enumerate() {
            ToolName::new(tool.name.clone()).map_err(|_| RuntimeError::StaleAuthority)?;
            if tool.revision.trim().is_empty()
                || tool.scope.trim().is_empty()
                || tool.parameters.get("type").and_then(Value::as_str) != Some("object")
                || (index > 0 && tools[index - 1].name == tool.name)
            {
                return Err(RuntimeError::Format("invalid tool registry".into()));
            }
            if pending_metadata_has_credential(&tool.metadata(), &tool.parameters) {
                return Err(RuntimeError::CredentialInToolMetadata);
            }
        }
        Ok(Self(tools))
    }

    /// Host-resolved names only. A grant refresh requires checkpoint negotiation,
    /// rather than silently changing the catalog of an in-flight model turn.
    pub fn granted(&self, names: &[&str]) -> Result<Self, RuntimeError> {
        Self::new(
            self.0
                .iter()
                .filter(|tool| names.contains(&tool.name.as_str()))
                .cloned()
                .collect(),
        )
    }

    pub fn get(&self, name: &str) -> Result<&RegisteredTool, RuntimeError> {
        self.0
            .iter()
            .find(|tool| tool.name == name)
            .ok_or(RuntimeError::StaleAuthority)
    }

    pub fn digest(&self) -> String {
        digest_json(self)
    }

    pub fn definitions(&self) -> Result<Vec<ToolDefinition>, RuntimeError> {
        // Revalidate even after deserialization; private fields are not a trust boundary.
        Self::new(self.0.clone())?;
        self.0
            .iter()
            .map(|tool| {
                Ok(ToolDefinition::new(
                    ToolName::new(tool.name.clone()).map_err(|_| RuntimeError::StaleAuthority)?,
                    tool.description.clone(),
                    tool.parameters.clone(),
                ))
            })
            .collect()
    }

    pub(crate) fn binding_revision(&self) -> ToolRevision {
        ToolRevision {
            revision: self.digest(),
            name: "registry".into(),
            description: "trusted host catalog".into(),
        }
    }
}

impl RegisteredTool {
    fn metadata(&self) -> ToolRevision {
        ToolRevision {
            revision: self.revision.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn tool(name: &str) -> RegisteredTool {
        RegisteredTool {
            name: name.into(),
            revision: "v1".into(),
            description: name.into(),
            parameters: json!({"type":"object","properties":{"path":{"type":"string"}}}),
            scope: format!("tool:{name}"),
            artifact_output: false,
        }
    }
    #[test]
    fn registry_binds_schema_revision_and_granted_tools() {
        let registry = ToolRegistry::new(vec![tool("write"), tool("read")]).unwrap();
        assert_eq!(registry.definitions().unwrap().len(), 2);
        assert_eq!(
            registry.digest(),
            ToolRegistry::new(vec![tool("read"), tool("write")])
                .unwrap()
                .digest()
        );
        let read = registry.granted(&["read"]).unwrap();
        assert!(read.get("write").is_err());
        assert_ne!(registry.digest(), read.digest());
        let mut changed = tool("read");
        changed.revision = "v2".into();
        assert_ne!(
            read.digest(),
            ToolRegistry::new(vec![changed]).unwrap().digest()
        );
        let mut changed = tool("read");
        changed.parameters["properties"]["path"]["type"] = json!("integer");
        assert_ne!(
            read.digest(),
            ToolRegistry::new(vec![changed]).unwrap().digest()
        );
        assert!(ToolRegistry::new(vec![tool("read"), tool("read")]).is_err());
        assert!(registry.granted(&[]).is_err());
    }
}
