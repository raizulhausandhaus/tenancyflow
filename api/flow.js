import { createPrivateKey } from "node:crypto";
import { compactDecrypt } from "jose";

const okJson = (res, bodyObj) => {
  res.setHeader("Content-Type", "application/json");
  return res.status(200).send(JSON.stringify(bodyObj));
};

export default async function handler(req, res) {
  try {
    if (req.method === "GET") return okJson(res, { status: "ok" });
    if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

    // Safely parse JSON
    let body = req.body && typeof req.body === "object" ? req.body : {};
    if (!Object.keys(body).length) {
      const raw = await new Promise((resolve) => {
        let data = "";
        req.on("data", (c) => (data += c));
        req.on("end", () => resolve(data));
      });
      try { body = JSON.parse(raw || "{}"); } catch { body = {}; }
    }

    // 1) Meta "sign public key" / verification challenge
    if (body.challenge) {
      return okJson(res, { challenge: body.challenge });
    }

    // 2) Meta Health Check — reply with Base64-encoded text (NOT JSON)
    // Meta doesn't document a single fixed shape; they add a special health/test call.
    // We detect it by absence of business payload and presence of a test marker OR the health check header.
    const isHealthCheck =
      body.health_check === true ||
      body.type === "health_check" ||
      req.headers["x-meta-health-check"] === "1";

    if (isHealthCheck) {
      const base64 = Buffer.from("ok").toString("base64"); // "b2s="
      res.setHeader("Content-Type", "text/plain");
      return res.status(200).send(base64);
    }

    // 3) Live traffic: decrypt if a JWE is present
    const jwe =
      body.encrypted_flow_data ||
      body.encrypted_flow_data_v2 ||
      (body.data && body.data.encrypted_flow_data) ||
      null;

    let decrypted = null;

    if (jwe && process.env.FLOW_PRIVATE_PEM) {
      try {
        const privateKey = createPrivateKey(process.env.FLOW_PRIVATE_PEM);
        const { plaintext } = await compactDecrypt(jwe, privateKey);
        const text = new TextDecoder().decode(plaintext);
        decrypted = JSON.parse(text);
      } catch (e) {
        console.error("Flow decryption error:", e?.message || e);
      }
    }

    // 4) Forward to your automation (Power Automate / Make / etc.)
    if (process.env.MAKE_WEBHOOK_URL) {
      try {
        await fetch(process.env.MAKE_WEBHOOK_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(decrypted || body)
        });
      } catch (e) {
        console.error("Forward failed:", e?.message || e);
      }
    }

    // 5) Acknowledge normal posts (or return a navigate action if you choose)
    return res.status(200).end();
  } catch (err) {
    console.error("Handler error:", err?.message || err);
    return res.status(200).end(); // Avoid retries
  }
}
