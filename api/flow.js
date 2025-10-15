import { createPrivateKey } from "node:crypto";
import { compactDecrypt } from "jose";

/**
 * Vercel Node API route
 * - Handles Meta Flow endpoint handshake (challenge)
 * - Decrypts encrypted Flow payloads (JWE) with your private key (FLOW_PRIVATE_PEM)
 * - Forwards the decrypted (or original) payload to your Power Automate webhook (https://default8851c2c5fa204fdc88d7995c154473.aa.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/fd077defbc3c43b6ae39408351756b3a/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=fi0A1BDxbO1EF7YP9KZhaqW2AUk0420xGpmWEF6JoSs)
 */
const ok = (res, body = null) => {
  if (body === null) return res.status(200).end();
  res.setHeader("Content-Type", "application/json");
  return res.status(200).send(JSON.stringify(body));
};

export default async function handler(req, res) {
  try {
    if (req.method === "GET") return ok(res, { status: "ok" });
    if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

    let body = req.body || {};
    if (!body || typeof body !== "object") {
      const raw = await new Promise((resolve) => {
        let data = "";
        req.on("data", (chunk) => (data += chunk));
        req.on("end", () => resolve(data));
      });
      try { body = JSON.parse(raw || "{}"); } catch { body = {}; }
    }

    // A) Meta "sign public key" / verification challenge
    if (body && body.challenge) {
      return ok(res, { challenge: body.challenge });
    }

    // B) Live traffic: decrypt if encrypted JWE is present
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

    // C) Forward to Power Automate (optional)
    if (process.env.https://default8851c2c5fa204fdc88d7995c154473.aa.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/fd077defbc3c43b6ae39408351756b3a/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=fi0A1BDxbO1EF7YP9KZhaqW2AUk0420xGpmWEF6JoSs) {
      try {
        await fetch(process.env.https://default8851c2c5fa204fdc88d7995c154473.aa.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/fd077defbc3c43b6ae39408351756b3a/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=fi0A1BDxbO1EF7YP9KZhaqW2AUk0420xGpmWEF6JoSs, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(decrypted || body)
        });
      } catch (e) {
        console.error("Forward to Power Automate failed:", e?.message || e);
      }
    }

    return ok(res);
  } catch (err) {
    console.error("Handler error:", err?.message || err);
    return res.status(200).end(); // ack to Meta anyway
  }
}
