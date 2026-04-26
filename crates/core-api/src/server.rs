use std::net::SocketAddr;
use std::sync::Arc;

use axum::{http::HeaderMap, middleware::{self, Next}, response::Response, Router};
use core_runtime::Runtime;
use tracing::info;

use crate::{compat, native::NativeState};
use core_runtime::UrlTester;

pub struct ApiServer {
    pub addr: SocketAddr,
    pub runtime: Arc<Runtime>,
    pub secret: Option<String>,
    pub clash_compat: bool,
    pub urltest: Arc<UrlTester>,
}

impl ApiServer {
    pub async fn run(self) -> anyhow::Result<()> {
        let state = NativeState {
            runtime: self.runtime.clone(),
            started_at: std::time::Instant::now(),
            secret: self.secret.clone(),
            urltest: self.urltest.clone(),
        };
        let mut app = Router::new();
        app = app.nest("/v1", crate::native::router(state.clone()));
        if self.clash_compat {
            app = app.merge(compat::router(state.clone()));
        }
        let listener_secret = self.secret.clone();
        let app = app.layer(middleware::from_fn(move |headers: HeaderMap, req, next| {
            let secret = listener_secret.clone();
            check_secret(secret, headers, req, next)
        }));
        let listener = tokio::net::TcpListener::bind(self.addr).await?;
        info!(addr = %self.addr, "api listening");
        axum::serve(listener, app).await?;
        Ok(())
    }
}

async fn check_secret(
    secret: Option<String>,
    headers: HeaderMap,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let path = req.uri().path();
    // 静态/根路径不要求 secret
    if path == "/" || path.starts_with("/ui") {
        return next.run(req).await;
    }
    let Some(expect) = secret else {
        return next.run(req).await;
    };
    if expect.is_empty() {
        return next.run(req).await;
    }
    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-secret").and_then(|v| v.to_str().ok()));
    if provided == Some(expect.as_str()) {
        next.run(req).await
    } else {
        axum::response::IntoResponse::into_response((
            axum::http::StatusCode::UNAUTHORIZED,
            "missing or wrong secret",
        ))
    }
}
