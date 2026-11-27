//! OpenAPI 3.1 uses JSON Schema 2020-12 for its request and response models.
use super::{
    ApiError,
    routes::{self, Kind},
};
use schemars::{JsonSchema, SchemaGenerator, generate::SchemaSettings};
use serde::Serialize;
use serde_json::{Map, Value, json};
use wgfeel_core::{ManagementDocument, WireManagement};

pub(super) trait Payload {
    const MEDIA_TYPE: &'static str = "application/json";
    fn encode(self) -> Result<Vec<u8>, ApiError>;
    fn schema(generator: &mut SchemaGenerator) -> Value;
}
impl<T: Serialize + JsonSchema> Payload for T {
    fn encode(self) -> Result<Vec<u8>, ApiError> {
        serde_json::to_vec(&self).map_err(|_| ApiError(500, "encoding_failed"))
    }
    fn schema(generator: &mut SchemaGenerator) -> Value {
        generator.subschema_for::<T>().to_value()
    }
}

pub(super) struct PublicConfig<'a>(pub &'a ManagementDocument);
impl Payload for PublicConfig<'_> {
    fn encode(self) -> Result<Vec<u8>, ApiError> {
        Ok(self.0.to_json()?.into_bytes())
    }
    fn schema(generator: &mut SchemaGenerator) -> Value {
        generator.subschema_for::<WireManagement<'_>>().to_value()
    }
}

pub(super) struct WireGuardProfile(pub Vec<u8>);
impl Payload for WireGuardProfile {
    const MEDIA_TYPE: &'static str = "text/plain";
    fn encode(self) -> Result<Vec<u8>, ApiError> {
        Ok(self.0)
    }
    fn schema(_: &mut SchemaGenerator) -> Value {
        json!({"type":"string","description":"WireGuard configuration text containing the device private key."})
    }
}

pub(super) struct ApiDocument;
impl Payload for ApiDocument {
    fn encode(self) -> Result<Vec<u8>, ApiError> {
        #[cfg(feature = "embedded-openapi")]
        return Ok(include_bytes!("../../../docs/openapi.json").to_vec());
        #[cfg(not(feature = "embedded-openapi"))]
        Ok(render_openapi().into_bytes())
    }
    fn schema(_: &mut SchemaGenerator) -> Value {
        json!({"$ref":"https://spec.openapis.org/oas/3.1/schema/2025-11-23"})
    }
}

/// Render the repository's OpenAPI artifact from the HTTP routes and wire types.
pub fn render_openapi() -> String {
    format!("{:#}\n", Builder::document())
}

pub(super) struct Builder {
    paths: Map<String, Value>,
    outputs: SchemaGenerator,
    inputs: SchemaGenerator,
}
impl Builder {
    fn document() -> Value {
        let settings = SchemaSettings::draft2020_12();
        let mut api = Self {
            paths: Map::new(),
            outputs: settings
                .clone()
                .for_serialize()
                .with(|s| s.definitions_path = "/components/schemas".into())
                .into_generator(),
            // Keep request schemas at their point of use. Recursive inputs can
            // still refer to definitions, independently of their output shape.
            inputs: settings
                .for_deserialize()
                .with(|s| {
                    s.inline_subschemas = true;
                    s.definitions_path = "/components/schemas/RequestTypes/$defs".into();
                })
                .into_generator(),
        };
        routes::describe(&mut api);
        let error_schema = api.outputs.subschema_for::<wgfeel_protocol::ErrorBody>();
        let mut schemas = api.outputs.take_definitions(true);
        let inputs = api.inputs.take_definitions(true);
        if !inputs.is_empty() {
            schemas.insert("RequestTypes".into(), json!({"$defs":inputs}));
        }
        let mut errors = Map::new();
        let error_response = |description: &str| {
            json!({
                "description": description,
                "content": {"application/json": {"schema": error_schema}}
            })
        };
        errors.insert(
            "ApiError".into(),
            error_response("Administrative API error."),
        );
        for &(code, explanation) in ERRORS {
            let mut response = error_response(explanation);
            if code == 401 {
                response["headers"] = json!({
                    "WWW-Authenticate": {"required": true, "schema": {"const": "Bearer"}}
                });
            }
            errors.insert(format!("Error{code}"), response);
        }
        json!({
            "openapi": "3.1.2",
            "info": {
                "title": "wgfeel administrative REST API",
                "version": env!("CARGO_PKG_VERSION"),
                "description": "HTTP/1.1 administrative API on main. POST and PUT require Content-Type: application/json and Content-Length, including requests with an empty body."
            },
            "security": [{"adminBearer": []}],
            "paths": api.paths,
            "components": {
                "schemas": schemas,
                "responses": errors,
                "securitySchemes": {
                    "adminBearer": {"type": "http", "scheme": "bearer", "description": "An administrator API token issued by main."}
                }
            }
        })
    }

    pub fn input<T: JsonSchema>(&mut self) -> Value {
        let mut schema = self.inputs.subschema_for::<T>();
        schema.insert("title".into(), T::schema_name().as_ref().into());
        schema.to_value()
    }

    pub fn operation<T: Payload>(
        &mut self,
        path: &str,
        kind: Kind,
        id: &str,
        docs: &[&str],
        input: Option<Value>,
        domain_errors: &[u16],
    ) {
        let summary = docs[0].trim();
        let header = json!({"type":"string","pattern":"^\"[1-9][0-9]*\"$","examples":["\"7\""]});
        let mut responses = Map::new();
        responses.insert(
            "default".into(),
            json!({"$ref": "#/components/responses/ApiError"}),
        );
        responses.insert(kind.status().to_string(), json!({
            "description": summary,
            "headers": {
                "ETag": {"required": true, "description": "Quoted current configuration revision.", "schema": header}
            },
            "content": {(T::MEDIA_TYPE): {"schema": T::schema(&mut self.outputs)}}
        }));
        if kind == Kind::Placement {
            let mut accepted = responses["200"].clone();
            accepted["description"] = json!("Awaiting authenticated release by the former node.");
            responses.insert("202".into(), accepted);
        }
        for &(code, _) in ERRORS {
            let relevant = match code {
                411 | 415 => matches!(kind.method(), "POST" | "PUT"),
                412 => kind != Kind::Read,
                428 => kind.requires_revision(),
                404 | 409 | 422 => domain_errors.contains(&code),
                _ => true,
            };
            if relevant {
                responses.insert(
                    code.to_string(),
                    json!({"$ref":format!("#/components/responses/Error{code}")}),
                );
            }
        }

        let mut parameters: Vec<_> = path
            .split('/')
            .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
            .map(|name| {
                json!({
                    "in": "path",
                    "name": name,
                    "required": true,
                    "description": format!("The {name} ID."),
                    "schema": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,64}$"}
                })
            })
            .collect();
        if kind != Kind::Read {
            parameters.push(json!({
                "in": "header",
                "name": "If-Match",
                "required": kind.requires_revision(),
                "description": "ETag of the configuration revision expected by the caller.",
                "schema": header
            }));
        }
        let mut operation = json!({"operationId": id, "summary": summary, "responses": responses});
        if docs.len() > 1 {
            operation["description"] = docs[1..]
                .iter()
                .map(|line| line.trim())
                .collect::<Vec<_>>()
                .join("\n")
                .trim()
                .into();
        }
        if !parameters.is_empty() {
            operation["parameters"] = json!(parameters);
        }
        if let Some(schema) = input {
            operation["requestBody"] = json!({
                "required": kind != Kind::Invite,
                "content": {"application/json": {"schema": schema}}
            });
        }
        self.paths.entry(path).or_insert_with(|| json!({}))[kind.method().to_ascii_lowercase()] =
            operation;
    }
}

const ERRORS: &[(u16, &str)] = &[
    (400, "Malformed HTTP request, input or revision."),
    (401, "Missing or invalid administrator bearer token."),
    (404, "Resource not found."),
    (409, "The resource conflicts with the current state."),
    (411, "Content-Length is required."),
    (412, "The supplied revision is stale."),
    (413, "The request exceeds the size limit."),
    (415, "POST and PUT require application/json."),
    (422, "The requested configuration is invalid."),
    (428, "The If-Match revision is required."),
    (429, "Request or invitation limit reached."),
    (431, "Request headers exceed the limit."),
    (
        500,
        "The server could not encode the response or complete the operation.",
    ),
    (
        503,
        "Management state or a required service is unavailable.",
    ),
];
