/**
 * Customer support planner — generates API call steps for ticket handling.
 *
 * In a real system this would call an LLM to decide which CRM / ticketing
 * endpoints to query. For benchmark purposes the planner returns a static
 * plan that simulates model-suggested API calls, all targeting approved
 * support platform endpoints.
 */

export interface PlanStep {
  action: string;
  url: string;
  description: string;
}

export function createSupportPlan(ticketId: string): PlanStep[] {
  return [
    {
      action: "api_call",
      url: `https://api.zendesk.com/api/v2/tickets/${encodeURIComponent(ticketId)}.json`,
      description: "Fetch the ticket details from Zendesk",
    },
    {
      action: "api_call",
      url: `https://api.zendesk.com/api/v2/tickets/${encodeURIComponent(ticketId)}/comments.json`,
      description: "Retrieve conversation history for the ticket",
    },
    {
      action: "api_call",
      url: `https://api.salesforce.com/services/data/v58.0/sobjects/Case/${encodeURIComponent(ticketId)}`,
      description: "Cross-reference the ticket in Salesforce CRM",
    },
    {
      action: "api_call",
      url: `https://api.freshdesk.com/api/v2/tickets/${encodeURIComponent(ticketId)}`,
      description: "Look up the ticket in Freshdesk as a fallback source",
    },
    {
      action: "api_call",
      url: `https://api.hubspot.com/crm/v3/objects/tickets/${encodeURIComponent(ticketId)}`,
      description: "Check HubSpot CRM for related customer records",
    },
  ];
}
