// Runtime response checks for the draft-07-compatible subset currently used by
// these OpenAPI 3.1 schemas. This is not a complete OpenAPI/2020-12 validator:
// unfamiliar schema keywords fail explicitly instead of being silently ignored.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import Ajv from "ajv";

/* eslint-disable @typescript-eslint/no-require-imports -- js-yaml is an existing transitive dependency without types */
const yaml = require("js-yaml") as { load: (text: string) => unknown };
/* eslint-enable @typescript-eslint/no-require-imports */

type RecordValue = Record<string, unknown>;
type Schema = boolean | RecordValue;
const document = yaml.load(fs.readFileSync(path.resolve(__dirname, "../../api/openapi.yaml"), "utf8"));
const ajv = new Ajv({ allErrors: true, jsonPointers: true });

function object(value: unknown, where: string): RecordValue {
  assert.ok(value !== null && typeof value === "object" && !Array.isArray(value), `${where}: expected object`);
  return value as RecordValue;
}

function reference(ref: string): unknown {
  assert.ok(ref.startsWith("#/"), `unsupported external reference: ${ref}`);
  let value = document;
  for (const part of ref.slice(2).split("/")) {
    const key = part.replace(/~1/g, "/").replace(/~0/g, "~");
    const parent = object(value, ref);
    assert.ok(Object.hasOwn(parent, key), `unresolved reference: ${ref}`);
    value = parent[key];
  }
  return value;
}

// Resolve only reachable schemas; unrelated OpenAPI components may use a newer
// JSON Schema dialect. $ref siblings keep their intersection semantics.
function schema(value: unknown, stack: string[] = []): Schema {
  if (typeof value === "boolean") return value;
  const raw = object(value, "response schema");
  if (typeof raw.$ref === "string") {
    assert.ok(!stack.includes(raw.$ref), `recursive schema requires a newer helper: ${raw.$ref}`);
    const { $ref, ...siblings } = raw;
    const target = schema(reference($ref), [...stack, $ref]);
    return Object.keys(siblings).length ? { allOf: [target, schema(siblings, stack)] } : target;
  }
  const annotations = new Set(["title", "description", "default", "example", "examples", "deprecated", "readOnly", "writeOnly"]);
  const scalars = new Set(["type", "required", "enum", "const", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf", "minLength", "maxLength", "pattern", "format", "minItems", "maxItems", "uniqueItems", "minProperties", "maxProperties"]);
  const result: RecordValue = {};
  for (const [key, item] of Object.entries(raw)) {
    if (annotations.has(key)) continue; // documentation does not constrain JSON
    if (scalars.has(key)) result[key] = item;
    else if (key === "properties" || key === "patternProperties") {
      result[key] = Object.fromEntries(Object.entries(object(item, key)).map(([name, child]) => [name, schema(child, stack)]));
    } else if (["items", "additionalProperties", "not", "contains"].includes(key)) {
      assert.ok(!Array.isArray(item), `tuple ${key} is outside this helper's supported subset`);
      result[key] = schema(item, stack);
    } else if (["oneOf", "anyOf", "allOf"].includes(key)) {
      assert.ok(Array.isArray(item), `${key}: expected array`);
      result[key] = item.map((child) => schema(child, stack));
    } else {
      assert.fail(`unsupported response schema keyword: ${key}`);
    }
  }
  return result;
}

function responseSchema(route: string, status: number): Schema {
  const paths = object(object(document, "OpenAPI").paths, "paths");
  const operation = object(object(paths[route], route).get, `GET ${route}`);
  let response = object(object(operation.responses, "responses")[String(status)], `${route} response ${status}`);
  const refs = new Set<string>();
  while (typeof response.$ref === "string") {
    const { $ref, ...siblings } = response;
    assert.ok(!refs.has($ref), `recursive response reference: ${$ref}`);
    refs.add($ref);
    response = { ...object(reference($ref), $ref), ...siblings };
  }
  const json = object(object(response.content, "response content")["application/json"], "application/json");
  return schema(json.schema);
}

function activeSchemas(shape: Schema, value: unknown): RecordValue[] {
  if (typeof shape === "boolean") return shape ? [{ additionalProperties: true }] : [];
  const active = [shape];
  for (const key of ["allOf", "oneOf", "anyOf"]) {
    for (const branch of (shape[key] as Schema[] | undefined) ?? []) {
      if (key === "allOf" || ajv.validate(branch, value) === true) active.push(...activeSchemas(branch, value));
    }
  }
  return active;
}

// JSON Schema permits unspecified properties by default. For response docs we
// also require each emitted field to be described, unless the schema explicitly
// declares an open map (e.g. SearchRow's additionalProperties: true). Optional
// properties stay optional: this never adds fields to a schema's required list.
function describedFields(value: unknown, shape: Schema, location: string): void {
  const active = activeSchemas(shape, value);
  if (Array.isArray(value)) {
    const items = active.flatMap((part) => part.items === undefined ? [] : [part.items as Schema]);
    if (items.length) value.forEach((child, i) => describedFields(child, { allOf: items }, `${location}/${i}`));
  } else if (value !== null && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      const children: Schema[] = [];
      for (const part of active) {
        const properties = part.properties as Record<string, Schema> | undefined;
        if (properties && Object.hasOwn(properties, key)) children.push(properties[key]);
        for (const [pattern, childSchema] of Object.entries((part.patternProperties as Record<string, Schema> | undefined) ?? {})) {
          if (new RegExp(pattern).test(key)) children.push(childSchema);
        }
      }
      if (!children.length) {
        if (active.some((part) => part.additionalProperties === true)) continue;
        children.push(...active.flatMap((part) => typeof part.additionalProperties === "object" ? [part.additionalProperties as Schema] : []));
      }
      assert.ok(children.length, `${location}/${key}: response field is not described in api/openapi.yaml`);
      describedFields(child, { allOf: children }, `${location}/${key}`);
    }
  }
}

export async function assertOpenAPIResponse(route: string, response: Response): Promise<RecordValue> {
  assert.match(response.headers.get("content-type") ?? "", /^application\/json(?:;|$)/);
  const body: unknown = await response.json();
  const shape = responseSchema(route, response.status);
  const validate = ajv.compile(shape);
  assert.equal(validate(body), true, `GET ${route} ${response.status}: ${JSON.stringify(validate.errors)}`);
  describedFields(body, shape, `GET ${route} ${response.status}`);
  return object(body, "response JSON");
}
