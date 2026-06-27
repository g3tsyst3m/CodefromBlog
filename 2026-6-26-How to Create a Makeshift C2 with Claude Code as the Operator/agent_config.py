AGENT_ID = "yourid"

DOMAIN        = "yourdomain.com"
SECRET        = "your-secret-key-here"
ENROLL_KEY    = "your-enroll-key-here"
MCP_PORT      = 8765
LISTENER_PORT = 8080

TUNNEL_NAME  = f"remote-agent-{AGENT_ID}"
LISTENER_URL = f"https://agent-{AGENT_ID}.{DOMAIN}"
MCP_URL      = f"https://mcp-{AGENT_ID}.{DOMAIN}"
INIT_URL     = f"https://init-{AGENT_ID}.{DOMAIN}"
