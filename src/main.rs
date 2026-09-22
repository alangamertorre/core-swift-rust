use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower_http::cors::{Any, CorsLayer};

// ---------- Estado compartido: el pool de conexiones a Supabase ----------
#[derive(Clone)]
struct AppState {
    pool: PgPool,
}

// ---------- Respuestas al frontend ----------
type Resp = (StatusCode, Json<Value>);

fn ok(data: Value) -> Resp {
    (StatusCode::OK, Json(json!({ "ok": true, "data": data })))
}

fn error(code: StatusCode, msg: &str) -> Resp {
    (code, Json(json!({ "ok": false, "error": msg })))
}

fn db_error(e: sqlx::Error) -> Resp {
    eprintln!("Error de base de datos: {e}");
    error(StatusCode::INTERNAL_SERVER_ERROR, "Error de base de datos")
}

// ---------- Datos que envía el JS ----------
// Todos los campos menos `mode` son opcionales; usa los que necesites.
#[derive(Deserialize)]
struct UserReq {
    mode: String,
    user_name: Option<String>,
    email: Option<String>,
    password: Option<String>,
    name: Option<String>,
    new_password: Option<String>, // solo para mode = "update"
}

// ---------- Utilidades de contraseña ----------
fn hashear(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

fn password_correcta(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

// Comprueba user_name + password. Devuelve Err(respuesta) si no coinciden.
async fn verificar_usuario(pool: &PgPool, user_name: &str, password: &str) -> Result<(), Resp> {
    let hash: Option<String> =
        sqlx::query_scalar("SELECT password FROM usuarios WHERE user_name = $1")
            .bind(user_name)
            .fetch_optional(pool)
            .await
            .map_err(db_error)?;

    match hash {
        Some(h) if password_correcta(password, &h) => Ok(()),
        // Mismo mensaje si no existe o si la contraseña falla (no revela cuál)
        _ => Err(error(
            StatusCode::UNAUTHORIZED,
            "Usuario o contraseña incorrectos",
        )),
    }
}

// =====================================================================
// FUNCIÓN 1: managerUser(mode, user_name, ...)
// Ruta: POST /managerUser
// =====================================================================
async fn manager_user(State(state): State<AppState>, Json(req): Json<UserReq>) -> Resp {
    match req.mode.as_str() {
        // ---------- GET: leer un usuario ----------
        "get" => {
            let Some(user_name) = req.user_name else {
                return error(StatusCode::BAD_REQUEST, "Falta user_name");
            };

            let fila: Result<Option<Value>, sqlx::Error> = sqlx::query_scalar(
                "SELECT row_to_json(u) FROM (
                    SELECT id, user_name, email, name, fecha_registro, ultimo_acceso, programas_download
                    FROM usuarios WHERE user_name = $1
                 ) u",
            )
            .bind(user_name)
            .fetch_optional(&state.pool)
            .await;

            match fila {
                Ok(Some(usuario)) => ok(usuario),
                Ok(None) => error(StatusCode::NOT_FOUND, "Usuario no encontrado"),
                Err(e) => db_error(e),
            }
        }

        // ---------- REGISTER: crear usuario ----------
        "register" => {
            let (Some(user_name), Some(email), Some(password), Some(name)) =
                (req.user_name, req.email, req.password, req.name)
            else {
                return error(
                    StatusCode::BAD_REQUEST,
                    "Faltan campos: user_name, email, password, name",
                );
            };

            if password.len() < 8 {
                return error(
                    StatusCode::BAD_REQUEST,
                    "La contraseña debe tener al menos 8 caracteres",
                );
            }

            let Ok(hash) = hashear(&password) else {
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Error al procesar la contraseña",
                );
            };

            let res: Result<String, sqlx::Error> = sqlx::query_scalar(
                "INSERT INTO usuarios (user_name, email, password, name)
                 VALUES ($1, $2, $3, $4)
                 RETURNING id::text",
            )
            .bind(user_name)
            .bind(email)
            .bind(hash)
            .bind(name)
            .fetch_one(&state.pool)
            .await;

            match res {
                Ok(id) => ok(json!({ "id": id })),
                Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                    error(StatusCode::CONFLICT, "El usuario o el email ya existe")
                }
                Err(e) => db_error(e),
            }
        }

        // ---------- LOGIN: comprobar contraseña y actualizar ultimo_acceso ----------
        "login" => {
            let (Some(user_name), Some(password)) = (req.user_name, req.password) else {
                return error(
                    StatusCode::BAD_REQUEST,
                    "Faltan campos: user_name, password",
                );
            };

            if let Err(resp) = verificar_usuario(&state.pool, &user_name, &password).await {
                return resp;
            }

            // Actualiza ultimo_acceso y devuelve el usuario (sin la contraseña)
            let res: Result<Value, sqlx::Error> = sqlx::query_scalar(
                "WITH u AS (
                    UPDATE usuarios SET ultimo_acceso = now()
                    WHERE user_name = $1
                    RETURNING id, user_name, email, name, fecha_registro, ultimo_acceso, programas_download
                 )
                 SELECT row_to_json(u) FROM u",
            )
            .bind(user_name)
            .fetch_one(&state.pool)
            .await;

            match res {
                Ok(usuario) => ok(usuario),
                Err(e) => db_error(e),
            }
        }

        // ---------- UPDATE: cambiar email, name y/o contraseña ----------
        // Requiere user_name + password (la actual). Nuevos valores opcionales:
        // email, name, new_password
        "update" => {
            let (Some(user_name), Some(password)) = (req.user_name, req.password) else {
                return error(
                    StatusCode::BAD_REQUEST,
                    "Faltan campos: user_name, password",
                );
            };

            if let Err(resp) = verificar_usuario(&state.pool, &user_name, &password).await {
                return resp;
            }

            let nuevo_hash = match req.new_password {
                Some(p) => {
                    if p.len() < 8 {
                        return error(
                            StatusCode::BAD_REQUEST,
                            "La nueva contraseña debe tener al menos 8 caracteres",
                        );
                    }
                    match hashear(&p) {
                        Ok(h) => Some(h),
                        Err(_) => {
                            return error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Error al procesar la contraseña",
                            )
                        }
                    }
                }
                None => None,
            };

            // COALESCE: si el valor nuevo es NULL, se deja el que ya había
            let res = sqlx::query(
                "UPDATE usuarios
                 SET email    = COALESCE($2, email),
                     name     = COALESCE($3, name),
                     password = COALESCE($4, password)
                 WHERE user_name = $1",
            )
            .bind(user_name)
            .bind(req.email)
            .bind(req.name)
            .bind(nuevo_hash)
            .execute(&state.pool)
            .await;

            match res {
                Ok(_) => ok(json!({ "actualizado": true })),
                Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                    error(StatusCode::CONFLICT, "Ese email ya está en uso")
                }
                Err(e) => db_error(e),
            }
        }

        // ---------- DELETE: borrar la cuenta ----------
        // Requiere user_name + password
        "delete" => {
            let (Some(user_name), Some(password)) = (req.user_name, req.password) else {
                return error(
                    StatusCode::BAD_REQUEST,
                    "Faltan campos: user_name, password",
                );
            };

            if let Err(resp) = verificar_usuario(&state.pool, &user_name, &password).await {
                return resp;
            }

            let res = sqlx::query("DELETE FROM usuarios WHERE user_name = $1")
                .bind(user_name)
                .execute(&state.pool)
                .await;

            match res {
                Ok(r) => ok(json!({ "borrados": r.rows_affected() })),
                Err(e) => db_error(e),
            }
        }

        _ => error(StatusCode::BAD_REQUEST, "mode no válido"),
    }
}

// =====================================================================
// FUNCIÓN 2: manager_productos
// Ruta: POST /managerProductos
// Recibe { producto: id o nombre, so: "windows" | "mac" | "linux" }
// Devuelve la URL del instalador
// =====================================================================
#[derive(Deserialize)]
struct ProductoReq {
    producto: Value,  // id (número) o nombre (texto)
    so: String,       // "windows", "mac" o "linux"
    version: String,  // ej. "1.0.0"
}

async fn manager_productos(State(state): State<AppState>, Json(req): Json<ProductoReq>) -> Resp {
    let so = req.so.to_lowercase();
    let so = match so.as_str() {
        "windows" | "win" => "windows",
        "mac" | "macos" | "mac-os" => "mac",
        "linux" | "ubuntu" => "linux",
        _ => return error(StatusCode::BAD_REQUEST, "so debe ser windows, mac o linux"),
    };

    if req.version.trim().is_empty() {
        return error(StatusCode::BAD_REQUEST, "Falta version");
    }

    // El producto puede llegar como id o como nombre
    let clave = match &req.producto {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => return error(StatusCode::BAD_REQUEST, "producto debe ser un id o un nombre"),
    };

    // #>> baja por el JSON usando un array de claves: data_json -> so -> version
    let fila: Result<Option<(i32, String, Option<String>)>, sqlx::Error> = sqlx::query_as(
        "SELECT id, name, data_json #>> ARRAY[$2, $3]
         FROM productos
         WHERE id::text = $1 OR lower(name) = lower($1)
         LIMIT 1",
    )
    .bind(&clave)
    .bind(so)
    .bind(&req.version)
    .fetch_optional(&state.pool)
    .await;

    let (id, name, ruta) = match fila {
        Ok(Some(f)) => f,
        Ok(None) => return error(StatusCode::NOT_FOUND, "Producto no encontrado"),
        Err(e) => return db_error(e),
    };

    let Some(ruta) = ruta.filter(|r| !r.is_empty()) else {
        return error(
            StatusCode::NOT_FOUND,
            "No existe esa versión para ese producto y sistema operativo",
        );
    };

    // URL completa: si la ruta ya es una URL se usa tal cual
    let url: String = if ruta.starts_with("http") {
        ruta
    } else {
        let base: String = std::env::var("STORAGE_URL").unwrap_or_default();
        format!(
            "{}/{}",
            base.trim_end_matches('/'),
            ruta.trim_start_matches('/')
        )
    };

    if let Err(e) =
        sqlx::query("UPDATE productos SET number_downloads = number_downloads + 1 WHERE id = $1")
            .bind(id)
            .execute(&state.pool)
            .await
    {
        eprintln!("No se pudo contar la descarga: {e}");
    }

    ok(json!({ "id": id, "name": name, "so": so, "version": req.version, "url": url }))
}

// =====================================================================
// listaProductos: devuelve TODOS los productos como array
// Ruta: GET /listaProductos
// =====================================================================
async fn lista_productos(State(state): State<AppState>) -> Resp {
    let filas: Result<Vec<Value>, sqlx::Error> = sqlx::query_scalar(
        "SELECT row_to_json(p) FROM (
            SELECT id, name, img, description_readme_path, number_downloads
            FROM productos
            ORDER BY name
         ) p",
    )
    .fetch_all(&state.pool)
    .await;

    match filas {
        Ok(lista) => ok(json!(lista)),
        Err(e) => db_error(e),
    }
}

// =====================================================================
// FUNCIÓN 3: (ponle el nombre que quieras)
// Ruta: POST /manager3
// =====================================================================
async fn manager_noticias(State(state): State<AppState>) -> Resp {
    // TODO: tu SQL
    let filas: Result<Vec<Value>, sqlx::Error> = sqlx::query_scalar(
        "SELECT row_to_json(p) FROM (
            SELECT img, title, description
            FROM noticias
            ORDER BY name
         ) p",
    )
    .fetch_all(&state.pool)
    .await;

    match filas {
        Ok(lista) => ok(json!(lista)),
        Err(e) => db_error(e),
    }
}

// ---------- Arranque del servidor ----------
#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let url = std::env::var("DATABASE_URL").expect("Falta DATABASE_URL");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("No se pudo conectar a Supabase");
    println!("Conectado a Supabase");

    // CORS abierto para pruebas. En producción pon solo el dominio de tu frontend.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/managerUser", post(manager_user))
        .route("/managerProductos", post(manager_productos))
        .route("/listaProductos", get(lista_productos))
        .route("/manager_noticias", post(manager_noticias))
        .layer(cors)
        .with_state(AppState { pool });

    let puerto = std::env::var("PORT").unwrap_or_else(|_| "3000".into());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{puerto}"))
        .await
        .unwrap();
    println!("Escuchando en el puerto {puerto}");
    axum::serve(listener, app).await.unwrap();
}
