from fastmcp import FastMCP
import sentinel

mcp = FastMCP("Sentinel-MCP", log_level="INFO")


@mcp.tool(
    name="get_incidents",
    description="Fetches Sentinel incidents. Returns a list of incidents with title, severity, status, and description.",
)
def get_incidents():
    incidents = sentinel.get_sentinel_incidents()
    return incidents


@mcp.tool(
    name="run_kql_query",
    description="Execute a KQL query against the Sentinel Log Analytics workspace. Returns rows as JSON objects. Example query: 'SecurityIncident | take 5'.",
)
def run_kql_tool(query: str):
    return sentinel.run_kql_query(query)


if __name__ == "__main__":
    mcp.run(
        transport="http",
        host="0.0.0.0",           # Bind to all interfaces
        port=9000,                # Custom port
        log_level="DEBUG",        # Override global log level
    )
