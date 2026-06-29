//
//  heimdall
//  src/routes/threat_models.rs
//

use actix_web::{HttpMessage, HttpRequest, HttpResponse, web};
use serde::Deserialize;
use uuid::Uuid;

use crate::middleware::auth::AuthenticatedUser;
use crate::models::ApiResponse;
use crate::state::AppState;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/threat-models")
            .route("/{id}", web::get().to(get_threat_model))
            .route("/{id}", web::patch().to(update_threat_model))
            .route("/{id}/surfaces", web::post().to(add_surface))
            .route("/{id}/surfaces/{index}", web::delete().to(remove_surface))
            .route("/{id}/boundaries", web::post().to(add_boundary))
            .route(
                "/{id}/boundaries/{index}",
                web::delete().to(remove_boundary),
            )
            .route("/{id}/data-flows", web::post().to(add_data_flow))
            .route(
                "/{id}/data-flows/{index}",
                web::delete().to(remove_data_flow),
            ),
    );
}

#[derive(Debug, Deserialize)]
struct UpdateThreatModelRequest {
    summary: Option<String>,
    boundaries: Option<serde_json::Value>,
    surfaces: Option<serde_json::Value>,
    data_flows: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct AddSurfaceRequest {
    name: String,
    risk: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AddBoundaryRequest {
    name: String,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AddDataFlowRequest {
    name: String,
    from: String,
    to: String,
    description: Option<String>,
}

fn extract_user_id(req: &HttpRequest) -> Uuid {
    req.extensions()
        .get::<AuthenticatedUser>()
        .map(|user| user.id)
        .unwrap_or_else(Uuid::nil)
}

async fn load_owned_threat_model(
    state: &AppState,
    id: Uuid,
    user_id: Uuid,
) -> Result<crate::models::db_models::ThreatModel, HttpResponse> {
    match state.db.get_threat_model_by_id_for_user(id, user_id).await {
        Ok(Some(tm)) => Ok(tm),
        Ok(None) => {
            Err(HttpResponse::NotFound()
                .json(ApiResponse::<()>::error(404, "Threat model not found")))
        }
        Err(error) => Err(HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error(500, format!("{error}")))),
    }
}

async fn get_threat_model(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> HttpResponse {
    let id = path.into_inner();
    match load_owned_threat_model(&state, id, extract_user_id(&req)).await {
        Ok(tm) => HttpResponse::Ok().json(ApiResponse::ok(tm)),
        Err(response) => response,
    }
}

async fn update_threat_model(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<UpdateThreatModelRequest>,
) -> HttpResponse {
    let id = path.into_inner();

    if let Err(response) = load_owned_threat_model(&state, id, extract_user_id(&req)).await {
        return response;
    }

    if let Some(ref summary) = body.summary
        && let Err(e) = state
            .db
            .update_threat_model_field(id, "summary", &serde_json::json!(summary))
            .await
    {
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error(500, format!("{e}")));
    }
    if let Some(ref boundaries) = body.boundaries
        && let Err(e) = state
            .db
            .update_threat_model_field(id, "boundaries_json", boundaries)
            .await
    {
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error(500, format!("{e}")));
    }
    if let Some(ref surfaces) = body.surfaces
        && let Err(e) = state
            .db
            .update_threat_model_field(id, "surfaces_json", surfaces)
            .await
    {
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error(500, format!("{e}")));
    }
    if let Some(ref data_flows) = body.data_flows
        && let Err(e) = state
            .db
            .update_threat_model_field(id, "data_flows_json", data_flows)
            .await
    {
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error(500, format!("{e}")));
    }

    // Return updated model
    match load_owned_threat_model(&state, id, extract_user_id(&req)).await {
        Ok(tm) => HttpResponse::Ok().json(ApiResponse::ok(tm)),
        Err(response) => response,
    }
}

async fn add_surface(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<AddSurfaceRequest>,
) -> HttpResponse {
    let id = path.into_inner();
    let tm = match load_owned_threat_model(&state, id, extract_user_id(&req)).await {
        Ok(tm) => tm,
        Err(response) => return response,
    };

    let mut surfaces = tm
        .surfaces_json
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();

    surfaces.push(serde_json::json!({
        "name": body.name,
        "risk": body.risk.as_deref().unwrap_or("medium"),
        "description": body.description.as_deref().unwrap_or(""),
    }));

    match state
        .db
        .update_threat_model_field(
            id,
            "surfaces_json",
            &serde_json::Value::Array(surfaces.clone()),
        )
        .await
    {
        Ok(_) => HttpResponse::Ok().json(ApiResponse::ok(surfaces)),
        Err(e) => {
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(500, format!("{e}")))
        }
    }
}

async fn remove_surface(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<(Uuid, usize)>,
) -> HttpResponse {
    let (id, index) = path.into_inner();
    let tm = match load_owned_threat_model(&state, id, extract_user_id(&req)).await {
        Ok(tm) => tm,
        Err(response) => return response,
    };

    let mut surfaces = tm
        .surfaces_json
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();

    if index >= surfaces.len() {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(400, "Index out of bounds"));
    }

    surfaces.remove(index);

    match state
        .db
        .update_threat_model_field(
            id,
            "surfaces_json",
            &serde_json::Value::Array(surfaces.clone()),
        )
        .await
    {
        Ok(_) => HttpResponse::Ok().json(ApiResponse::ok(surfaces)),
        Err(e) => {
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(500, format!("{e}")))
        }
    }
}

async fn add_boundary(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<AddBoundaryRequest>,
) -> HttpResponse {
    let id = path.into_inner();
    let tm = match load_owned_threat_model(&state, id, extract_user_id(&req)).await {
        Ok(tm) => tm,
        Err(response) => return response,
    };

    let mut boundaries = tm
        .boundaries_json
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();

    boundaries.push(serde_json::json!({
        "name": body.name,
        "description": body.description.as_deref().unwrap_or(""),
    }));

    match state
        .db
        .update_threat_model_field(
            id,
            "boundaries_json",
            &serde_json::Value::Array(boundaries.clone()),
        )
        .await
    {
        Ok(_) => HttpResponse::Ok().json(ApiResponse::ok(boundaries)),
        Err(e) => {
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(500, format!("{e}")))
        }
    }
}

async fn remove_boundary(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<(Uuid, usize)>,
) -> HttpResponse {
    let (id, index) = path.into_inner();
    let tm = match load_owned_threat_model(&state, id, extract_user_id(&req)).await {
        Ok(tm) => tm,
        Err(response) => return response,
    };

    let mut boundaries = tm
        .boundaries_json
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();

    if index >= boundaries.len() {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(400, "Index out of bounds"));
    }

    boundaries.remove(index);

    match state
        .db
        .update_threat_model_field(
            id,
            "boundaries_json",
            &serde_json::Value::Array(boundaries.clone()),
        )
        .await
    {
        Ok(_) => HttpResponse::Ok().json(ApiResponse::ok(boundaries)),
        Err(e) => {
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(500, format!("{e}")))
        }
    }
}

async fn add_data_flow(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<AddDataFlowRequest>,
) -> HttpResponse {
    let id = path.into_inner();
    let tm = match load_owned_threat_model(&state, id, extract_user_id(&req)).await {
        Ok(tm) => tm,
        Err(response) => return response,
    };

    let mut flows = tm
        .data_flows_json
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();

    flows.push(serde_json::json!({
        "name": body.name,
        "from": body.from,
        "to": body.to,
        "description": body.description.as_deref().unwrap_or(""),
    }));

    match state
        .db
        .update_threat_model_field(
            id,
            "data_flows_json",
            &serde_json::Value::Array(flows.clone()),
        )
        .await
    {
        Ok(_) => HttpResponse::Ok().json(ApiResponse::ok(flows)),
        Err(e) => {
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(500, format!("{e}")))
        }
    }
}

async fn remove_data_flow(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<(Uuid, usize)>,
) -> HttpResponse {
    let (id, index) = path.into_inner();
    let tm = match load_owned_threat_model(&state, id, extract_user_id(&req)).await {
        Ok(tm) => tm,
        Err(response) => return response,
    };

    let mut flows = tm
        .data_flows_json
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();

    if index >= flows.len() {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(400, "Index out of bounds"));
    }

    flows.remove(index);

    match state
        .db
        .update_threat_model_field(
            id,
            "data_flows_json",
            &serde_json::Value::Array(flows.clone()),
        )
        .await
    {
        Ok(_) => HttpResponse::Ok().json(ApiResponse::ok(flows)),
        Err(e) => {
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(500, format!("{e}")))
        }
    }
}
