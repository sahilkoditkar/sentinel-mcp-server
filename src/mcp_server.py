from fastmcp import FastMCP
import sentinel_client

mcp = FastMCP("Sentinel-MCP", log_level="INFO")


@mcp.tool(
    name="run_kql_query",
    description="Execute a KQL query against the Sentinel Log Analytics workspace. Returns rows as JSON objects. Example query: 'SecurityIncident | take 5'.",
)
def run_kql(query: str):
    return sentinel_client.run_kql_query(query)


@mcp.tool(
    name="get_incidents",
    description="Fetches Sentinel incidents. Returns a list of incidents with title, severity, status, and description.",
)
def get_incidents():
    return sentinel_client.get_sentinel_incidents()


@mcp.tool(
    name="get_incident_by_id",
    description="Fetches a single Sentinel incident by its ID.",
)
def get_incident_by_id(incident_id: str):
    return sentinel_client.get_incident_by_id(incident_id)


@mcp.tool(
    name="update_incident",
    description="Updates an existing incident. Allows modifying status, severity, and owner.",
)
def update_incident(incident_id: str, status: str = None, severity: str = None, owner: dict = None):
    return sentinel_client.update_incident(incident_id, status, severity, owner)


@mcp.tool(
    name="get_incident_comments",
    description="Retrieves all comments for a given incident.",
)
def get_incident_comments(incident_id: str):
    return sentinel_client.get_incident_comments(incident_id)


@mcp.tool(
    name="add_incident_comment",
    description="Adds a comment to a specific incident.",
)
def add_incident_comment(incident_id: str, message: str):
    return sentinel_client.add_incident_comment(incident_id, message)


@mcp.tool(
    name="get_incident_alerts",
    description="Gets all alerts for a given incident.",
)
def get_incident_alerts(incident_id: str):
    return sentinel_client.get_incident_alerts(incident_id)


if __name__ == "__main__":
    mcp.run(
        transport="http",
        host="0.0.0.0",           # Bind to all interfaces
        port=9000,                # Custom port
        log_level="DEBUG",        # Override global log level
    )