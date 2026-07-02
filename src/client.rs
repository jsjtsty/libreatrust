use crate::error::{AtrError, AtrResult};
use crate::resource::{ResourceSnapshot, route};
use crate::sign::calc_request_sig;
use crate::types::{ClientConfig, CookieRecord, ProtocolKind, RouteDecision, SessionMaterial};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct AtrClient {
    config: ClientConfig,
    session: Option<SessionMaterial>,
    resource: Option<ResourceSnapshot>,
    resource_bytes: Option<Vec<u8>>,
}

impl AtrClient {
    pub fn new(config: ClientConfig) -> AtrResult<Self> {
        if config.server_host.is_empty() {
            return Err(AtrError::InvalidArgument("server_host is empty".into()));
        }
        if config.server_port == 0 {
            return Err(AtrError::InvalidArgument("server_port is zero".into()));
        }
        Ok(Self {
            config,
            session: None,
            resource: None,
            resource_bytes: None,
        })
    }

    pub fn set_session(&mut self, session: SessionMaterial) {
        self.session = Some(session);
    }

    pub fn clear_session(&mut self) {
        self.session = None;
    }

    pub fn session(&self) -> Option<&SessionMaterial> {
        self.session.as_ref()
    }

    pub fn set_resource(&mut self, resource: ResourceSnapshot) {
        self.resource = Some(resource);
    }

    pub fn set_resource_bytes(&mut self, bytes: Vec<u8>) {
        self.resource_bytes = Some(bytes);
    }

    pub fn resource(&self) -> Option<&ResourceSnapshot> {
        self.resource.as_ref()
    }

    pub fn resource_bytes(&self) -> Option<&[u8]> {
        self.resource_bytes.as_deref()
    }

    pub fn route_tcp(&self, host: &str, port: u16) -> RouteDecision {
        self.route(host, port, ProtocolKind::Tcp)
    }

    pub fn route_udp(&self, host: &str, port: u16) -> RouteDecision {
        self.route(host, port, ProtocolKind::Udp)
    }

    pub fn route_icmp(&self, host: &str) -> RouteDecision {
        self.route(host, 0, ProtocolKind::Icmp)
    }

    fn route(&self, host: &str, port: u16, protocol: ProtocolKind) -> RouteDecision {
        if let Some(resource) = self.resource.as_ref() {
            route(resource, host, port, protocol)
        } else {
            RouteDecision::Direct
        }
    }

    pub fn best_node_for(&self, node_group_id: &str) -> Option<String> {
        self.resource.as_ref().and_then(|res| {
            res.best_nodes
                .get(node_group_id)
                .cloned()
                .or_else(|| res.best_nodes.get(&res.major_node_group).cloned())
        })
    }

    pub fn build_request_sig(&self, data: &[u8]) -> AtrResult<String> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| AtrError::InvalidState("session not set".into()))?;
        let key = hex::decode(&session.sign_key_hex)
            .map_err(|e| AtrError::InvalidArgument(format!("invalid sign key: {e}")))?;
        Ok(calc_request_sig(&key, data))
    }

    pub fn cookies(&self) -> Vec<CookieRecord> {
        self.session
            .as_ref()
            .map(|s| s.cookies.clone())
            .unwrap_or_default()
    }

    pub fn session_material_from_parts(
        &self,
        username: String,
        sid: String,
        device_id: String,
        connection_id: String,
        sign_key_hex: String,
    ) -> SessionMaterial {
        SessionMaterial {
            username,
            sid,
            device_id,
            connection_id,
            sign_key_hex,
            cookies: Vec::new(),
        }
    }

    pub fn client_config(&self) -> &ClientConfig {
        &self.config
    }

    pub fn choose_node_groups(&self) -> HashMap<String, String> {
        self.resource
            .as_ref()
            .map(|res| res.best_nodes.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{DomainResource, ResourceSnapshot};

    #[test]
    fn prefers_managed_route() {
        let mut snapshot = ResourceSnapshot::default();
        snapshot.domain_resources.insert(
            "example.com".into(),
            DomainResource {
                port_min: 443,
                port_max: 443,
                protocol: "tcp".into(),
                app_id: "app".into(),
                node_group_id: "group".into(),
            },
        );
        let mut client = AtrClient::new(ClientConfig {
            server_host: "svc".into(),
            server_port: 443,
            ..Default::default()
        })
        .unwrap();
        client.set_resource(snapshot);
        let decision = client.route_tcp("example.com", 443);
        assert!(matches!(decision, RouteDecision::Managed(_)));
    }
}
