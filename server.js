// server.js
// npm i express node-fetch@2 dotenv nodemailer
const express = require("express");
const fetch = require("node-fetch"); // v2
const nodemailer = require("nodemailer");
const crypto = require("crypto");
require("dotenv").config();

const app = express();

// --- Body parsers ---
// Use raw body only for the webhook route (needed for signature verification)
app.use("/api/webhooks/yoco", express.raw({ type: "*/*" }));

// JSON/urlencoded for the rest of the app
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static pages (index.html, success.html, cancel.html)
app.use(express.static("public"));

app.set("trust proxy", true);

// ---- Fixed amount: R2 (in cents) ----
const FIXED_AMOUNT_CENTS = 200;

// In-memory cache (fallback) to recover the note if metadata doesn’t include it
const notesByCheckout = new Map();

// Build our public base URL (works on Render/ngrok/custom domain)
function getBase(req) {
  const host = req.headers["x-forwarded-host"] || req.headers["x-original-host"] || req.get("host");
  const proto = (req.headers["x-forwarded-proto"] || "").split(",")[0] || "http";
  return `${proto}://${host}`;
}

// Email transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: (process.env.SMTP_PORT || "") === "465",
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

// Create checkout (hosted page) from the form (requires `note`)
app.post("/api/checkout", async (req, res) => {
  try {
    const base = getBase(req);
    const note = String((req.body?.note || "")).trim();
    if (!note) return res.status(400).json({ error: "Please enter the required reference." });

    const payload = {
      amount: FIXED_AMOUNT_CENTS,
      currency: "ZAR",
      description: `Payment – ${note}`,
      successUrl: `${base}/success.html`,
      cancelUrl: `${base}/index.html`,
      metadata: { note }, // try to keep the note with the checkout
    };

    const r = await fetch("https://payments.yoco.com/api/checkouts", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.YOCO_LIVE_SECRET}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const data = await r.json();
    if (!r.ok) return res.status(r.status).json(data);

    // Cache the note by checkout id as a fallback (not persistent across restarts)
    if (data.id && note) notesByCheckout.set(data.id, note);

    res.json({ redirectUrl: data.redirectUrl, checkoutId: data.id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message || "Server error" });
  }
});

// --- Yoco webhook (payment.succeeded / payment.failed) ---
// Verify signature per Yoco docs, then email details
app.post("/api/webhooks/yoco", async (req, res) => {
  try {
    const secret = process.env.YOCO_WEBHOOK_SECRET;
    if (!secret) {
      console.warn("[webhook] YOCO_WEBHOOK_SECRET not set");
      return res.sendStatus(200); // avoid retries until configured
    }

    // 1) Build signed content
    const id = req.headers["webhook-id"];
    const timestamp = req.headers["webhook-timestamp"];
    const signatureHeader = req.headers["webhook-signature"] || "";
    const rawBody = Buffer.isBuffer(req.body) ? req.body.toString("utf8") : String(req.body || "");

    // Optional: reject if timestamp too old (> 3 min) to prevent replay
    const now = Math.floor(Date.now() / 1000);
    if (!timestamp || Math.abs(now - Number(timestamp)) > 180) {
      console.warn("[webhook] timestamp outside threshold");
      return res.sendStatus(400);
    }

    const signedContent = `${id}.${timestamp}.${rawBody}`;

    // 2) Compute expected signature (strip "whsec_" prefix and base64-decode the remainder)
    const secretBytes = Buffer.from(secret.split("_")[1], "base64");
    const expectedSig = crypto.createHmac("sha256", secretBytes).update(signedContent).digest("base64");

    // 3) Compare with the first signature in header (format: "v1,<sig> v1,<sig> v2,<sig> ...")
    const first = signatureHeader.split(" ")[0] || "";
    const provided = first.split(",")[1] || "";
    if (!provided || !crypto.timingSafeEqual(Buffer.from(expectedSig), Buffer.from(provided))) {
      console.warn("[webhook] signature mismatch");
      return res.sendStatus(403);
    }

    // Parse the JSON once verified
    const event = JSON.parse(rawBody);
    const type = event?.type; // "payment.succeeded" | "payment.failed"
    const p = event?.payload || {};
    const status = p?.status || (type === "payment.succeeded" ? "succeeded" : "failed");
    const amountCents = Number(p?.amount || 0);
    const checkoutId = p?.metadata?.checkoutId;
    const note = p?.metadata?.note || (checkoutId ? notesByCheckout.get(checkoutId) : null) || "N/A";

    // Only act on payment events we care about
    if (type === "payment.succeeded" || type === "payment.failed") {
      // Fire-and-forget email; respond 200 immediately so Yoco stops retrying
      (async () => {
        try {
          const amountRand = (amountCents / 100).toFixed(2);
          await transporter.sendMail({
            from: process.env.NOTIFY_FROM || process.env.SMTP_USER,
            to: process.env.NOTIFY_TO,
            subject: `Payment ${status.toUpperCase()} – R${amountRand} – Ref: ${note}`,
            text: `Status: ${status}\nAmount: R${amountRand}\nReference: ${note}\nCheckout ID: ${checkoutId || "unknown"}`,
            html: `
              <h3>Payment ${status}</h3>
              <p><b>Amount:</b> R${amountRand}</p>
              <p><b>Reference:</b> ${note}</p>
              <p><b>Checkout ID:</b> ${checkoutId || "unknown"}</p>
            `,
          });
        } catch (err) {
          console.error("[email] failed:", err.message);
        }
      })();
    }

    res.sendStatus(200);
  } catch (e) {
    console.error("[webhook] error:", e);
    // Still 200 to avoid infinite retries if our code throws unexpectedly
    res.sendStatus(200);
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening on port ${PORT}`));

