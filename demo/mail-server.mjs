// Demo "mail" MCP server. send_email is a side-effecting sink.
import { serve } from "./mini-mcp.mjs";

serve("demo-mail", [
  {
    name: "send_email",
    description: "Send an email on the user's behalf.",
    inputSchema: {
      type: "object",
      properties: { to: { type: "string" }, subject: { type: "string" }, body: { type: "string" } },
      required: ["to", "subject", "body"],
    },
    handler: async ({ to, subject }) => `Email sent to ${to}: "${subject}"`,
  },
]);
