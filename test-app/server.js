// A deliberately vulnerable vibe-coded server for testing vibecheck
const express = require("express");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");

const app = express();

// VC009: CORS allows all origins
app.use(cors());

// VC001: Hardcoded API keys
const STRIPE_SECRET_KEY = "sk_live_FAKE_TEST_KEY_DO_NOT_USE_abcdefghijklmnop";
const OPENAI_API_KEY = "sk-FAKE-TEST-KEY-not-real-abcdefghijklmnopqrstuvwxyz";

// VC004: Supabase service role key in server (exposed via API)
const supabase = createClient(
  "https://xyzcompany.supabase.co",
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhtdXB0cHBsZnZpaWZyYndtbXR2Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTY5ODc2NTI3MCwiZXhwIjoyMDE0MzQxMjcwfQ.fake_service_role_key_for_testing"
);

// VC003: No authentication on API routes
app.get("/api/users", async (req, res) => {
  const { data } = await supabase.from("users").select("*");
  res.json(data);
});

// VC006: SQL injection via string concatenation
app.get("/api/search", async (req, res) => {
  const query = req.query.q;
  const { data } = await supabase.rpc("search_users", {
    search_query: query,
  });
  // Even worse: raw SQL
  const result = await db.query(`SELECT * FROM products WHERE name LIKE '%${query}%'`);
  res.json(result);
});

// VC005: Stripe webhook without signature verification
app.post("/api/webhooks/stripe", async (req, res) => {
  const event = req.body;
  if (event.type === "checkout.session.completed") {
    await supabase
      .from("subscriptions")
      .update({ status: "active" })
      .eq("user_id", event.data.object.client_reference_id);
  }
  res.json({ received: true });
});

// VC008: No rate limiting on the entire server
app.listen(3000, () => console.log("Server running on port 3000"));
