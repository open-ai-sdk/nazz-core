//! Native Rig models on a host-authorized, DNS-pinned unary TLS transport.
//! Credentials are supplied by the host for each turn, never serialized.
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use nazz_core::{
    ActorGrant, CredentialRoute, EndpointGrant, ProviderApi, ProviderDispatch, authorize_dispatch,
};
use rig::http_client::{
    self, HttpClientExt, LazyBody, MultipartForm, Request, Response, StreamingResponse,
};
use rig::wasm_compat::WasmCompatSend;
use rig::{DynModel, operation::Completion};

use crate::RuntimeError;

#[derive(Clone)]
pub struct ProviderConfig {
    pub api: ProviderApi,
    pub model: String,
    pub endpoint: EndpointGrant,
    /// API root only. Responses/chat use /v1; Anthropic uses the origin root.
    pub base_url: String,
}

impl ProviderConfig {
    /// Build a real callable pinned Rig model. Does not make a network request.
    /// SIWC needs a separately verified consent/identity adapter, not a bearer
    /// token relabeled as an API key.
    pub fn model(
        &self,
        actor: &ActorGrant,
        secret: String,
    ) -> Result<DynModel<Completion>, RuntimeError> {
        if secret.is_empty() {
            return Err(RuntimeError::StaleAuthority);
        }
        self.configured_model(actor, secret)
    }

    /// Pinned Rig descriptors do not require account credentials or network IO.
    /// The empty credential never escapes this describe-only path.
    pub fn preparation_capabilities(
        &self,
        actor: &ActorGrant,
    ) -> Result<rig::completion::ProviderCapabilities, RuntimeError> {
        Ok(self
            .configured_model(actor, String::new())?
            .capabilities()
            .completion)
    }

    fn configured_model(
        &self,
        actor: &ActorGrant,
        secret: String,
    ) -> Result<DynModel<Completion>, RuntimeError> {
        if actor.tenant_id != self.endpoint.tenant_id
            || actor.revoked
            || self.endpoint.route != CredentialRoute::ApiKey
            || self.model.trim().is_empty()
        {
            return Err(RuntimeError::StaleAuthority);
        }
        let base = reqwest::Url::parse(&self.base_url).map_err(|_| refused())?;
        if base.scheme() != "https"
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.host_str() != Some(self.endpoint.host.as_str())
            || base.port_or_known_default() != Some(self.endpoint.port)
            || self.endpoint.scheme != "https"
        {
            return Err(refused());
        }
        match self.api {
            ProviderApi::OpenAiResponses | ProviderApi::OpenAiChatCompletions
                if self.endpoint.host != "api.openai.com" =>
            {
                return Err(refused());
            }
            ProviderApi::AnthropicMessages if self.endpoint.host != "api.anthropic.com" => {
                return Err(refused());
            }
            _ => {}
        }
        let suffix = match self.api {
            ProviderApi::OpenAiResponses => "/responses",
            ProviderApi::AnthropicMessages => "/v1/messages",
            _ => "/chat/completions",
        };
        let target = format!("{}{suffix}", self.base_url.trim_end_matches('/'));
        let transport = rig::http_client::DynHttpClient::new(GrantedHttp {
            endpoint: self.endpoint.clone(),
            api: self.api,
            target,
        });
        match self.api {
            ProviderApi::AnthropicMessages => {
                let mut config = rig::providers::anthropic::AnthropicConfig::new(secret);
                config.base_url = self.base_url.clone();
                Ok(config.connect(transport).completion(&self.model).erase())
            }
            _ => {
                let mut config = rig::providers::openai::OpenAIConfig::new(secret);
                config.base_url = self.base_url.clone();
                let client = config.connect(transport);
                Ok(if self.api == ProviderApi::OpenAiResponses {
                    client.responses(&self.model).erase()
                } else {
                    client.chat(&self.model).erase()
                })
            }
        }
    }
}

fn refused() -> RuntimeError {
    RuntimeError::Rig("provider configuration refused".into())
}
fn transport_refused() -> http_client::Error {
    http_client::Error::instance(std::io::Error::other("provider transport refused"))
}

#[derive(Clone)]
struct GrantedHttp {
    endpoint: EndpointGrant,
    api: ProviderApi,
    target: String,
}

impl HttpClientExt for GrantedHttp {
    fn send<T, U>(
        &self,
        request: Request<T>,
    ) -> impl Future<Output = http_client::Result<Response<LazyBody<U>>>> + WasmCompatSend + 'static
    where
        T: Into<Bytes> + WasmCompatSend,
        U: From<Bytes> + WasmCompatSend + 'static,
    {
        let policy = self.clone();
        let (parts, body) = request.into_parts();
        let body: Bytes = body.into();
        async move {
            // Compare the actual wire target, not just the configured API root.
            if parts.method != http_client::Method::POST || parts.uri.to_string() != policy.target {
                return Err(transport_refused());
            }
            let addresses: Vec<SocketAddr> =
                tokio::net::lookup_host((policy.endpoint.host.as_str(), policy.endpoint.port))
                    .await
                    .map_err(|_| transport_refused())?
                    .collect();
            let dispatch = ProviderDispatch {
                tenant_id: policy.endpoint.tenant_id.clone(),
                api: policy.api,
                scheme: policy.endpoint.scheme.clone(),
                host: policy.endpoint.host.clone(),
                port: policy.endpoint.port,
                credential: CredentialRoute::ApiKey,
                resolved_peers: addresses
                    .iter()
                    .map(|address| address.ip().to_string())
                    .collect(),
                redirect_count: 0,
            };
            authorize_dispatch(&policy.endpoint, &dispatch).map_err(|_| transport_refused())?;
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(45))
                .connect_timeout(Duration::from_secs(10))
                .resolve_to_addrs(&policy.endpoint.host, &addresses)
                .build()
                .map_err(|_| transport_refused())?;
            let response = client
                .post(&policy.target)
                .headers(parts.headers)
                .body(body)
                .send()
                .await
                .map_err(|_| transport_refused())?;
            // Numeric status only: never expose provider bodies, headers or config.
            eprintln!("agent-provider: http_status={}", response.status().as_u16());
            let peer = response.remote_addr().ok_or_else(transport_refused)?;
            if !addresses.contains(&peer) || !response.status().is_success() {
                // Never retain a provider error body: it can reflect credentials.
                return Err(transport_refused());
            }
            let mut builder = Response::builder().status(response.status());
            *builder.headers_mut().ok_or_else(transport_refused)? = response.headers().clone();
            let lazy: LazyBody<U> = Box::pin(async move {
                let mut response = response;
                let mut bytes = Vec::new();
                while let Some(chunk) = response.chunk().await.map_err(|_| transport_refused())? {
                    if chunk.len() > 8 * 1024 * 1024 - bytes.len() {
                        return Err(transport_refused());
                    }
                    bytes.extend_from_slice(&chunk);
                }
                Ok(U::from(Bytes::from(bytes)))
            });
            builder.body(lazy).map_err(Into::into)
        }
    }

    #[expect(
        clippy::manual_async_fn,
        reason = "Match the transport trait future bounds without capturing self."
    )]
    fn send_multipart<U>(
        &self,
        _request: Request<MultipartForm>,
    ) -> impl Future<Output = http_client::Result<Response<LazyBody<U>>>> + WasmCompatSend + 'static
    where
        U: From<Bytes> + WasmCompatSend + 'static,
    {
        async { Err(transport_refused()) }
    }

    #[expect(
        clippy::manual_async_fn,
        reason = "Match the transport trait future bounds without capturing self."
    )]
    fn send_streaming<T>(
        &self,
        _request: Request<T>,
    ) -> impl Future<Output = http_client::Result<StreamingResponse>> + WasmCompatSend
    where
        T: Into<Bytes> + WasmCompatSend,
    {
        // The production driver deliberately requests unary completions only.
        async { Err(transport_refused()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nazz_core::{ActorId, TenantId, WorkspaceId};
    fn fixture() -> (ProviderConfig, ActorGrant) {
        let actor = ActorGrant {
            tenant_id: TenantId::new("a"),
            workspace_id: WorkspaceId::new("w"),
            actor_id: ActorId::new("u"),
            revision: 1,
            revoked: false,
        };
        let config = ProviderConfig {
            api: ProviderApi::OpenAiResponses,
            model: "gpt-5.2".into(),
            base_url: "https://api.openai.com/v1".into(),
            endpoint: EndpointGrant {
                tenant_id: actor.tenant_id.clone(),
                scheme: "https".into(),
                host: "api.openai.com".into(),
                port: 443,
                route: CredentialRoute::ApiKey,
                allow_private: false,
                pinned_peer: None,
            },
        };
        (config, actor)
    }
    #[test]
    fn credential_routes_and_actual_origin_fail_closed_without_io() {
        let (mut config, actor) = fixture();
        assert_eq!(
            config.model(&actor, "test-only".into()).unwrap().id(),
            Some("gpt-5.2")
        );
        config.endpoint.route = CredentialRoute::SiwcResponses;
        assert!(config.model(&actor, "test-only".into()).is_err());
        config.endpoint.route = CredentialRoute::ApiKey;
        config.base_url = "https://api.openai.com@foreign.example/v1".into();
        assert!(config.model(&actor, "test-only".into()).is_err());
        config.base_url = "https://api.openai.com/v1?token=bad".into();
        assert!(config.model(&actor, "test-only".into()).is_err());
    }
    #[test]
    fn foreign_tenant_cannot_build_account_model() {
        let (config, mut actor) = fixture();
        actor.tenant_id = TenantId::new("foreign");
        assert!(config.model(&actor, "test-only".into()).is_err());
    }
}
