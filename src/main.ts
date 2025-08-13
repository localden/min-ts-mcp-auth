import 'dotenv/config';
import express from "express";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import cors from "cors";
import { mcpAuthMetadataRouter, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { OAuthMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import { checkResourceAllowed } from "@modelcontextprotocol/sdk/shared/auth-utils.js";

// Config: centralize host/port to avoid repeating literals
const HOST = process.env.HOST || "localhost";
const PORT = Number(process.env.PORT) || 3000;

const AUTH_HOST = process.env.AUTH_HOST || HOST;
const AUTH_PORT = Number(process.env.AUTH_PORT) || 8080;
const AUTH_REALM = process.env.AUTH_REALM || "master";

// OAuth client credentials (from .env)
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || "mcp-server";
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || "";

const app = express();
// Parse JSON and capture raw body for logging
app.use(express.json({
  verify: (req: any, _res, buf) => {
    try {
      req.rawBody = buf?.toString() ?? '';
    } catch {
      req.rawBody = '';
    }
  }
}));

// CORS configuration
app.use(cors({
  origin: '*', // Configure appropriately for production
  exposedHeaders: ['Mcp-Session-Id'],
}));

// Request logger: logs every request with full headers and body (no redaction)
app.use((req: any, res: any, next) => {
  const start = Date.now();

  // Capture response body by wrapping write/end
  const chunks: Buffer[] = [];
  const originalWrite = res.write.bind(res);
  const originalEnd = res.end.bind(res);

  res.write = ((chunk: any, ...args: any[]) => {
    try {
      if (chunk !== undefined && chunk !== null) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
    } catch {}
    return originalWrite(chunk, ...args);
  }) as typeof res.write;

  res.end = ((chunk?: any, ...args: any[]) => {
    try {
      if (chunk !== undefined && chunk !== null) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      res.locals.__responseBody = Buffer.concat(chunks).toString('utf8');
    } catch {}
    return originalEnd(chunk, ...args);
  }) as typeof res.end;

  res.on('finish', () => {
    const durationMs = Date.now() - start;
    const length = res.get('Content-Length') ?? '-';
    const base = `${req.method} ${req.originalUrl} ${res.statusCode} ${length}b - ${durationMs}ms`;
    console.log(base);

    // Log request headers and body
    console.log('Request Headers:', req.headers);
    const reqBodyStr = (typeof req.rawBody === 'string' && req.rawBody.length > 0)
      ? req.rawBody
      : (typeof req.body === 'string' ? req.body : (req.body != null ? JSON.stringify(req.body) : ''));
    console.log('Request Body:', reqBodyStr);

    // Log response headers and body
    try {
      console.log('Response Headers:', res.getHeaders());
    } catch {}
    const respBodyStr = typeof res.locals?.__responseBody === 'string' ? res.locals.__responseBody : '';
    console.log('Response Body:', respBodyStr);
  });
  next();
});

// Set up OAuth
const mcpServerUrl = new URL(`http://${HOST}:${PORT}`);
// Important: ensure trailing slash so relative URLs resolve under the realm (not drop it)
const authServerUrl = new URL(`http://${AUTH_HOST}:${AUTH_PORT}/realms/${AUTH_REALM}/`);
const strictOAuth = false; // Set to true if you want strict resource checking

const oauthMetadata: OAuthMetadata = {
  issuer: authServerUrl.toString(),
  introspection_endpoint: new URL("protocol/openid-connect/token/introspect", authServerUrl).toString(),
  authorization_endpoint: new URL("protocol/openid-connect/auth", authServerUrl).toString(),
  token_endpoint: new URL("protocol/openid-connect/token", authServerUrl).toString(),
  response_types_supported: ["code"],
};

const tokenVerifier = {
  verifyAccessToken: async (token: string) => {
    console.log('[auth] verifyAccessToken called');
    const endpoint = oauthMetadata.introspection_endpoint;

    if (!endpoint) {
      console.error('[auth] no introspection endpoint in metadata');
      throw new Error('No token verification endpoint available in metadata');
    }

    const params = new URLSearchParams({
      token: token,
      client_id: OAUTH_CLIENT_ID,
    });
    if (OAUTH_CLIENT_SECRET) {
      params.set('client_secret', OAUTH_CLIENT_SECRET);
    }
    const tokenPreview = typeof token === 'string' ? `${token.slice(0, 12)}... (${token.length} chars)` : '<non-string>';
    console.log('[auth] introspection request', { endpoint, clientId: OAUTH_CLIENT_ID, hasClientSecret: !!OAUTH_CLIENT_SECRET, tokenPreview });

    let response: Response;
    try {
      response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params.toString()
      });
    } catch (e) {
      console.error('[auth] introspection fetch threw', e);
      throw e;
    }

    if (!response.ok) {
      const txt = await response.text();
      console.error('[auth] introspection non-OK', { status: response.status });
      console.log('');
      // Print the JSON (or raw text) body on its own line for readability
      try {
        // Try to pretty-print JSON if possible
        const obj = JSON.parse(txt);
        console.error(JSON.stringify(obj, null, 2));
      } catch {
        console.error(txt);
      }
      console.log('');
      throw new Error(`Invalid or expired token: ${txt}`);
    }

    let data: any;
    try {
      data = await response.json();
    } catch (e) {
      const txt = await response.text();
      console.error('[auth] failed to parse introspection JSON', { error: String(e), body: txt });
      throw e;
    }
    try {
      console.log('[auth] introspection response', {
        active: data?.active,
        aud: data?.aud,
        client_id: data?.client_id,
        scope: data?.scope,
        exp: data?.exp,
      });
    } catch {}

    if (strictOAuth) {
      console.log('[auth] strictOAuth enabled');
      if (!data.aud) {
        console.error('[auth] strictOAuth: missing aud');
        throw new Error(`Resource Indicator (RFC8707) missing`);
      }
      const allowed = checkResourceAllowed({ requestedResource: data.aud, configuredResource: mcpServerUrl });
      console.log('[auth] strictOAuth resource check', { requested: data.aud, configured: mcpServerUrl.toString(), allowed });
      if (!allowed) {
        throw new Error(`Expected resource indicator ${mcpServerUrl}, got: ${data.aud}`);
      }
    }

    // Convert the response to AuthInfo format
    return {
      token,
      clientId: data.client_id,
      scopes: data.scope ? data.scope.split(' ') : [],
      expiresAt: data.exp,
    };
  }
};

// Add metadata routes to the main MCP server
app.use(mcpAuthMetadataRouter({
  oauthMetadata,
  resourceServerUrl: mcpServerUrl,
  scopesSupported: ['mcp:tools'],
  resourceName: 'MCP Demo Server',
}));

const authMiddleware = requireBearerAuth({
  verifier: tokenVerifier,
  requiredScopes: [],
  resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpServerUrl),
});

// Map to store transports by session ID
const transports: { [sessionId: string]: StreamableHTTPServerTransport } = {};

// MCP POST endpoint with optional auth
const mcpPostHandler = async (req: express.Request, res: express.Response) => {
  // Check for existing session ID
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  let transport: StreamableHTTPServerTransport;

  if (sessionId && transports[sessionId]) {
    // Reuse existing transport
    transport = transports[sessionId];
  } else if (!sessionId && isInitializeRequest(req.body)) {
    // New initialization request
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (sessionId) => {
        // Store the transport by session ID
        transports[sessionId] = transport;
      },
      // DNS rebinding protection is disabled by default for backwards compatibility. If you are running this server
      // locally, make sure to set:
      // enableDnsRebindingProtection: true,
      // allowedHosts: ['127.0.0.1'],
    });

    // Clean up transport when closed
    transport.onclose = () => {
      if (transport.sessionId) {
        delete transports[transport.sessionId];
      }
    };
    const server = new McpServer({
      name: "example-server",
      version: "1.0.0"
    });

    // Add a simple addition tool
    server.registerTool("add",
      {
        title: "Addition Tool",
        description: "Add two numbers together",
        inputSchema: { 
          a: z.number().describe("First number to add"), 
          b: z.number().describe("Second number to add") 
        }
      },
      async ({ a, b }) => ({
        content: [{ type: "text", text: `${a} + ${b} = ${a + b}` }]
      })
    );

    // Add a multiplication tool
    server.registerTool("multiply",
      {
        title: "Multiplication Tool", 
        description: "Multiply two numbers together",
        inputSchema: {
          x: z.number().describe("First number to multiply"),
          y: z.number().describe("Second number to multiply")
        }
      },
      async ({ x, y }) => ({
        content: [{ type: "text", text: `${x} × ${y} = ${x * y}` }]
      })
    );

    // Connect to the MCP server
    await server.connect(transport);
  } else {
    // Invalid request
    res.status(400).json({
      jsonrpc: '2.0',
      error: {
        code: -32000,
        message: 'Bad Request: No valid session ID provided',
      },
      id: null,
    });
    return;
  }

  // Handle the request
  await transport.handleRequest(req, res, req.body);
};

// Reusable handler for GET and DELETE requests
const handleSessionRequest = async (req: express.Request, res: express.Response) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  if (!sessionId || !transports[sessionId]) {
    res.status(400).send('Invalid or missing session ID');
    return;
  }
  
  const transport = transports[sessionId];
  await transport.handleRequest(req, res);
};

app.post('/', authMiddleware, mcpPostHandler);
app.get('/', authMiddleware, handleSessionRequest);
app.delete('/', authMiddleware, handleSessionRequest);

app.listen(PORT, () => {
  console.log(`🚀 MCP Server running on ${mcpServerUrl.origin}`);
  console.log(`📡 MCP endpoint available at ${mcpServerUrl.origin}`);
  console.log(`🔐 OAuth metadata available at ${getOAuthProtectedResourceMetadataUrl(mcpServerUrl)}`);
});