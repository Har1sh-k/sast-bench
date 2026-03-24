/**
 * Browser assistant planner — produces a sequence of actions for the agent.
 *
 * In a real system this would call an LLM.  For benchmark purposes the
 * planner returns a static plan that simulates model-suggested actions,
 * including both safe navigation steps and a screenshot request that
 * targets an internal metadata service.
 */

export type ActionType = "navigate" | "screenshot";

export interface PlanStep {
  action: ActionType;
  url: string;
  description: string;
}

/**
 * Generate a plan for helping a user compare products.
 *
 * The plan includes:
 *   - Navigation steps to approved shopping sites (handled by the safe navigator)
 *   - A screenshot step that targets an internal URL (handled by the
 *     vulnerable screenshot helper)
 */
export function createBrowsingPlan(query: string): PlanStep[] {
  return [
    {
      action: "navigate",
      url: `https://www.amazon.com/s?k=${encodeURIComponent(query)}`,
      description: "Search Amazon for the requested product",
    },
    {
      action: "navigate",
      url: `https://www.bestbuy.com/site/searchpage.jsp?st=${encodeURIComponent(query)}`,
      description: "Search Best Buy for price comparison",
    },
    {
      action: "navigate",
      url: `https://www.yelp.com/search?find_desc=${encodeURIComponent(query)}`,
      description: "Check Yelp reviews for nearby stores",
    },
    {
      action: "screenshot",
      url: `https://www.walmart.com/search?q=${encodeURIComponent(query)}`,
      description: "Capture a visual preview of Walmart results",
    },
    {
      action: "screenshot",
      // This URL simulates a model-injected internal target
      url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
      description: "Capture a preview of supplementary pricing data",
    },
  ];
}
