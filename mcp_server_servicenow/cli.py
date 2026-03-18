"""
ServiceNow MCP Server CLI

This module provides the command-line interface for the ServiceNow MCP server.
"""

import argparse
import os
import sys
from dotenv import load_dotenv

from mcp_server_servicenow.server import ServiceNowMCP, create_basic_auth

def main():
    """Run the ServiceNow MCP server from the command line"""
    # Load environment variables from .env file if it exists
    load_dotenv()
    
    parser = argparse.ArgumentParser(description="ServiceNow MCP Server")
    parser.add_argument("--url", help="ServiceNow instance URL", default=os.environ.get("SERVICENOW_INSTANCE_URL"))
    parser.add_argument("--transport", help="Transport protocol (stdio or sse)", default="stdio", choices=["stdio", "sse"])
    parser.add_argument("--host", help="Host to bind (SSE only)", default=os.environ.get("MCP_HOST", "0.0.0.0"))
    parser.add_argument("--port", help="Port to bind (SSE only)", type=int, default=int(os.environ.get("MCP_PORT", "8000")))

    # ServiceNow authentication
    auth_group = parser.add_argument_group("ServiceNow Authentication")
    auth_group.add_argument("--username", help="ServiceNow username", default=os.environ.get("SERVICENOW_USERNAME"))
    auth_group.add_argument("--password", help="ServiceNow password", default=os.environ.get("SERVICENOW_PASSWORD"))
    auth_group.add_argument("--token", help="ServiceNow token", default=os.environ.get("SERVICENOW_TOKEN"))
    auth_group.add_argument("--client-id", help="ServiceNow OAuth client ID", default=os.environ.get("SERVICENOW_CLIENT_ID"))
    auth_group.add_argument("--client-secret", help="ServiceNow OAuth client secret", default=os.environ.get("SERVICENOW_CLIENT_SECRET"))

    # MCP server protection (SSE only)
    server_auth = parser.add_argument_group("MCP Server Auth (SSE only)")
    server_auth.add_argument("--server-client-id", help="Client ID required to connect to this server", default=os.environ.get("MCP_SERVER_CLIENT_ID"))
    server_auth.add_argument("--server-client-secret", help="Client secret required to connect to this server", default=os.environ.get("MCP_SERVER_CLIENT_SECRET"))
    server_auth.add_argument("--server-url", help="Public URL of this server (used in OAuth metadata)", default=os.environ.get("MCP_SERVER_URL"))
    
    args = parser.parse_args()
    
    # Check required parameters
    if not args.url:
        print("Error: ServiceNow instance URL is required")
        print("Set SERVICENOW_INSTANCE_URL environment variable or use --url")
        sys.exit(1)
    
    # Determine authentication method
    auth = None
    if args.token:
        from mcp_server_servicenow.server import create_token_auth
        auth = create_token_auth(args.token)
    elif args.client_id and args.client_secret and args.username and args.password:
        from mcp_server_servicenow.server import create_oauth_auth
        auth = create_oauth_auth(args.client_id, args.client_secret, args.username, args.password, args.url)
    elif args.username and args.password:
        auth = create_basic_auth(args.username, args.password)
    else:
        print("Error: Authentication credentials required")
        print("Either provide username/password, token, or OAuth credentials")
        sys.exit(1)
    
    # Create and run the server
    server = ServiceNowMCP(
        instance_url=args.url,
        auth=auth,
        server_client_id=args.server_client_id,
        server_client_secret=args.server_client_secret,
        server_url=args.server_url,
    )
    server.run(transport=args.transport, host=args.host, port=args.port)

if __name__ == "__main__":
    main()
