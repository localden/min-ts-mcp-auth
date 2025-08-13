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
app.use(express.json());

// CORS configuration
app.use(cors({
  origin: '*', // Configure appropriately for production
  exposedHeaders: ['Mcp-Session-Id'],
  allowedHeaders: ['Content-Type', 'mcp-session-id', 'Authorization'],
}));

// Set up OAuth
const mcpServerUrl = new URL(`http://${HOST}:${PORT}`);
const authServerUrl = new URL(`http://${AUTH_HOST}:${AUTH_PORT}/realms/${AUTH_REALM}`);
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
    const endpoint = oauthMetadata.introspection_endpoint;

    if (!endpoint) {
      throw new Error('No token verification endpoint available in metadata');
    }

    const params = new URLSearchParams({
      token: token,
      client_id: OAUTH_CLIENT_ID,
    });
    if (OAUTH_CLIENT_SECRET) {
      params.set('client_secret', OAUTH_CLIENT_SECRET);
    }

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString()
    });

    if (!response.ok) {
      throw new Error(`Invalid or expired token: ${await response.text()}`);
    }

    const data = await response.json();

    if (strictOAuth) {
      if (!data.aud) {
        throw new Error(`Resource Indicator (RFC8707) missing`);
      }
      if (!checkResourceAllowed({ requestedResource: data.aud, configuredResource: mcpServerUrl })) {
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

// Set up routes with auth middleware
app.post('/', authMiddleware, mcpPostHandler);
app.get('/', authMiddleware, handleSessionRequest);
app.delete('/', authMiddleware, handleSessionRequest);

app.listen(PORT, () => {
  console.log(`🚀 MCP Server running on ${mcpServerUrl.origin}`);
  console.log(`📡 MCP endpoint available at ${mcpServerUrl.origin}`);
  console.log(`🔐 OAuth metadata available at ${getOAuthProtectedResourceMetadataUrl(mcpServerUrl)}`);
});