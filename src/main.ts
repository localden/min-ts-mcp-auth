/**
 * EXPERIMENTAL: TypeScript MCP Server with OAuth Authentication
 * This implementation is experimental and subject to change.
 */

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
const CONFIG = {
  host: process.env.HOST || "localhost",
  port: Number(process.env.PORT) || 3000,
  auth: {
    host: process.env.AUTH_HOST || process.env.HOST || "localhost",
    port: Number(process.env.AUTH_PORT) || 8080,
    realm: process.env.AUTH_REALM || "master",
    clientId: process.env.OAUTH_CLIENT_ID || "mcp-server",
    clientSecret: process.env.OAUTH_CLIENT_SECRET || "",
  },
  strictOAuth: false,
};

function createOAuthUrls() {
  const authBaseUrl = new URL(`http://${CONFIG.auth.host}:${CONFIG.auth.port}/realms/${CONFIG.auth.realm}/`);
  return {
    issuer: authBaseUrl.toString(),
    introspection_endpoint: new URL("protocol/openid-connect/token/introspect", authBaseUrl).toString(),
    authorization_endpoint: new URL("protocol/openid-connect/auth", authBaseUrl).toString(),
    token_endpoint: new URL("protocol/openid-connect/token", authBaseUrl).toString(),
  };
}

function createRequestLogger() {
  return (req: any, res: any, next: any) => {
    const start = Date.now();
    const chunks: Buffer[] = [];
    const originalWrite = res.write.bind(res);
    const originalEnd = res.end.bind(res);

    res.write = ((chunk: any, ...args: any[]) => {
      if (chunk !== undefined && chunk !== null) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      return originalWrite(chunk, ...args);
    }) as typeof res.write;

    res.end = ((chunk?: any, ...args: any[]) => {
      if (chunk !== undefined && chunk !== null) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      res.locals.__responseBody = Buffer.concat(chunks).toString('utf8');
      return originalEnd(chunk, ...args);
    }) as typeof res.end;

    res.on('finish', () => {
      const duration = Date.now() - start;
      const length = res.get('Content-Length') ?? '-';
      console.log(`${req.method} ${req.originalUrl} ${res.statusCode} ${length}b - ${duration}ms`);
      console.log('Request Headers:', req.headers);
      
      const reqBody = req.rawBody || (req.body ? JSON.stringify(req.body) : '');
      console.log('Request Body:', reqBody);
      console.log('Response Headers:', res.getHeaders());
      console.log('Response Body:', res.locals?.__responseBody || '');
    });
    next();
  };
}

const app = express();

app.use(express.json({
  verify: (req: any, _res, buf) => {
    req.rawBody = buf?.toString() ?? '';
  }
}));

app.use(cors({
  origin: '*',
  exposedHeaders: ['Mcp-Session-Id'],
}));

app.use(createRequestLogger());

const mcpServerUrl = new URL(`http://${CONFIG.host}:${CONFIG.port}`);
const oauthUrls = createOAuthUrls();
const strictOAuth = CONFIG.strictOAuth;

const oauthMetadata: OAuthMetadata = {
  ...oauthUrls,
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
      client_id: CONFIG.auth.clientId,
    });
    
    if (CONFIG.auth.clientSecret) {
      params.set('client_secret', CONFIG.auth.clientSecret);
    }
    
    const tokenPreview = `${token.slice(0, 12)}... (${token.length} chars)`;
    console.log('[auth] introspection request', { 
      endpoint, 
      clientId: CONFIG.auth.clientId, 
      hasClientSecret: !!CONFIG.auth.clientSecret, 
      tokenPreview 
    });

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
      
      try {
        const obj = JSON.parse(txt);
        console.log(JSON.stringify(obj, null, 2));
      } catch {
        console.error(txt);
      }
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
    
    console.log('[auth] introspection response');
    console.log(JSON.stringify(data, null, 2));

    if (strictOAuth) {
      console.log('[auth] strictOAuth enabled');
      if (!data.aud) {
        console.error('[auth] strictOAuth: missing aud');
        throw new Error(`Resource Indicator (RFC8707) missing`);
      }
      const allowed = checkResourceAllowed({ requestedResource: data.aud, configuredResource: mcpServerUrl });
      console.log('[auth] strictOAuth resource check', { 
        requested: data.aud, 
        configured: mcpServerUrl.toString(), 
        allowed 
      });
      if (!allowed) {
        throw new Error(`Expected resource indicator ${mcpServerUrl}, got: ${data.aud}`);
      }
    }

    return {
      token,
      clientId: data.client_id,
      scopes: data.scope ? data.scope.split(' ') : [],
      expiresAt: data.exp,
    };
  }
};
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

const transports: { [sessionId: string]: StreamableHTTPServerTransport } = {};

function createMcpServer() {
  const server = new McpServer({
    name: "example-server",
    version: "1.0.0"
  });

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

  return server;
}

const mcpPostHandler = async (req: express.Request, res: express.Response) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  let transport: StreamableHTTPServerTransport;

  if (sessionId && transports[sessionId]) {
    transport = transports[sessionId];
  } else if (!sessionId && isInitializeRequest(req.body)) {
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (sessionId) => {
        transports[sessionId] = transport;
      },
    });

    transport.onclose = () => {
      if (transport.sessionId) {
        delete transports[transport.sessionId];
      }
    };

    const server = createMcpServer();
    await server.connect(transport);
  } else {
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

  await transport.handleRequest(req, res, req.body);
};

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

app.listen(CONFIG.port, () => {
  console.log(`🚀 MCP Server running on ${mcpServerUrl.origin}`);
  console.log(`📡 MCP endpoint available at ${mcpServerUrl.origin}`);
  console.log(`🔐 OAuth metadata available at ${getOAuthProtectedResourceMetadataUrl(mcpServerUrl)}`);
});