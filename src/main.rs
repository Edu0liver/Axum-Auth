#[allow(dead_code, unused)]
use axum::{
    Json, RequestPartsExt, Router,
    extract::{FromRef, FromRequestParts, State},
    http::{StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::sync::LazyLock;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET is not set");
    Keys::new(secret.as_bytes())
});

#[derive(Deserialize)]
struct CreateUserDTO {
    name: String,
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct AuthenticateUserDTO {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct AuthenticationResponse {
    token: String,
}

#[derive(Serialize)]
struct UserResponse {
    id: i32,
    name: String,
    email: String,
    created_at: Option<chrono::NaiveDateTime>,
    updated_at: Option<chrono::NaiveDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    sub: i32,
    exp: usize,
}

#[derive(Debug)]
enum AuthError {
    InvalidToken,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

fn internal_error<E>(err: E) -> (StatusCode, String)
where
    E: std::error::Error,
{
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let auth = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());

        let Some(auth) = auth else {
            return Err(AuthError::InvalidToken);
        };

        if !auth.starts_with("Bearer ") {
            return Err(AuthError::InvalidToken);
        }

        let token = &auth[7..];

        // Decode the user data
        let token_data = decode::<Claims>(token, &KEYS.decoding, &Validation::default())
            .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db_connection_str = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&db_connection_str)
        .await
        .expect("can't connect to database");

    let app = Router::new()
        .route("/users", get(get_users))
        .route("/users", post(create_user))
        .route("/auth", post(authenticate_user))
        .with_state(pool);

    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();

    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}

async fn get_users(
    State(pool): State<PgPool>,
    _claims: Claims,
) -> Result<Json<Vec<UserResponse>>, (StatusCode, String)> {
    let users = sqlx::query_as!(
        UserResponse,
        r#"
            SELECT id, name, email, created_at, updated_at
            FROM users
            ORDER BY id DESC
        "#
    )
    .fetch_all(&pool)
    .await
    .map_err(internal_error)?;

    Ok(Json(users))
}

async fn create_user(
    State(pool): State<PgPool>,
    Json(payload): Json<CreateUserDTO>,
) -> Result<Json<UserResponse>, (StatusCode, String)> {
    // validate fields!

    let user = sqlx::query_as!(
        UserResponse,
        r#"
            INSERT INTO users (name, email, password)
            VALUES ($1, $2, $3)
            RETURNING id, name, email, created_at, updated_at
        "#,
        payload.name,
        payload.email,
        bcrypt::hash(payload.password, 10).unwrap()
    )
    .fetch_one(&pool)
    .await
    .map_err(internal_error)?;

    Ok(Json(user))
}

async fn authenticate_user(
    State(pool): State<PgPool>,
    Json(payload): Json<AuthenticateUserDTO>,
) -> Result<Json<AuthenticationResponse>, (StatusCode, String)> {
    // validate fields!

    let user = sqlx::query!(
        r#"
            SELECT id, email, password
            FROM users
            WHERE email = $1
            ORDER BY id DESC
        "#m,
        payload.email
    )
    .fetch_optional(&pool)
    .await
    .map_err(internal_error)?;

    let Some(user) = user else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Email or password incorrect!".to_string(),
        ));
    };

    if !bcrypt::verify(&payload.password, &user.password).map_err(internal_error)? {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Email or password incorrect!".to_string(),
        ));
    };

    Ok(Json(AuthenticationResponse {
        token: encode(
            &Header::default(),
            &Claims {
                sub: user.id,
                exp: (Utc::now() + ChronoDuration::hours(24)).timestamp() as usize,
            },
            &KEYS.encoding,
        )
        .map_err(internal_error)?,
    }))
}
