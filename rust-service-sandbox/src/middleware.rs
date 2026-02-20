use tower_http::{
    cors::CorsLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
};
use tracing::Level;

pub fn create_trace_layer() -> TraceLayer<
    tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>,
    DefaultMakeSpan,
    DefaultOnResponse,
> {
    TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_response(DefaultOnResponse::new().level(Level::INFO))
}

pub fn create_cors_layer() -> CorsLayer {
    CorsLayer::permissive()
}
