// CIMD profile (mirrors e2e/goserver/profile_cimd.go): the OAuth provider with Client ID
// Metadata Documents. The metadata transport is an in-memory fake (the same document table
// as the Go profile): documents are served with Cache-Control: no-cache and an ETag, and
// conditional requests are answered with 304.
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { cimd } from "@better-auth/cimd";

const ETAG = '"v1"';

const documents = {
  "https://client.e2e.example/client.json": {
    client_id: "https://client.e2e.example/client.json", client_name: "E2E CIMD Client",
    client_uri: "https://client.e2e.example/", redirect_uris: ["https://client.e2e.example/callback"],
    token_endpoint_auth_method: "none", application_type: "web",
    grant_types: ["authorization_code", "refresh_token"], response_types: ["code"],
  },
  "https://native.e2e.example/client.json": {
    client_id: "https://native.e2e.example/client.json", client_name: "E2E Native Client",
    redirect_uris: ["http://127.0.0.1:7777/callback"], application_type: "native",
  },
  "https://mismatch.e2e.example/client.json": {
    client_id: "https://other.e2e.example/client.json", client_name: "Mismatch",
    redirect_uris: ["https://mismatch.e2e.example/callback"],
  },
  "https://secret.e2e.example/client.json": {
    client_id: "https://secret.e2e.example/client.json", client_name: "Secret",
    redirect_uris: ["https://secret.e2e.example/callback"], token_endpoint_auth_method: "client_secret_basic",
  },
  "https://forbidden.e2e.example/client.json": {
    client_id: "https://forbidden.e2e.example/client.json", client_name: "Forbidden",
    redirect_uris: ["https://forbidden.e2e.example/callback"], skip_consent: true,
  },
  "https://plain.e2e.example/client.json": {
    client_id: "https://plain.e2e.example/client.json", client_name: "Plain",
    redirect_uris: ["https://plain.e2e.example/callback"],
  },
};

async function fetchClientMetadataResource(input, init) {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  const doc = documents[url];
  if (!doc) throw new TypeError("network error");
  if (new Headers(init?.headers).get("if-none-match") === ETAG) {
    return new Response(null, { status: 304, headers: { "cache-control": "no-cache" } });
  }
  if (new URL(url).host === "plain.e2e.example") {
    return new Response(JSON.stringify(doc), { headers: { "content-type": "text/plain" } });
  }
  return Response.json(doc, { headers: { "cache-control": "no-cache", etag: ETAG } });
}

export default async function (options) {
  options.plugins = [
    ...(options.plugins ?? []),
    jwt(),
    oauthProvider({ loginPage: "/login", consentPage: "/consent" }),
    cimd({ fetchClientMetadataResource, metadataFetchPolicy: { minimumFetchInterval: 0 } }),
  ];
}
