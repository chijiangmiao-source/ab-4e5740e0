import type { Conclusion, ItemDraft } from "./types";

export interface ApiError {
  error: string;
  message: string;
  field?: string;
  fingerprint_existing?: string;
  fingerprint_incoming?: string;
  audit_id?: string;
}

export async function submitAudit(
  auditId: string,
  items: ItemDraft[],
): Promise<{ status: number; body: Conclusion | ApiError }> {
  const payload = {
    audit_id: auditId,
    items: items.map((it) => ({
      name: it.name,
      grouped: it.grouped,
      content_base64: it.contentBase64,
    })),
  };
  const res = await fetch("/api/audits", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const body = (await res.json()) as Conclusion | ApiError;
  return { status: res.status, body };
}

export async function reopenAudit(auditId: string): Promise<{
  status: number;
  body: Conclusion | ApiError;
}> {
  const res = await fetch(`/api/audits/${encodeURIComponent(auditId)}`, {
    method: "GET",
  });
  const body = (await res.json()) as Conclusion | ApiError;
  return { status: res.status, body };
}

export function isConclusion(b: Conclusion | ApiError): b is Conclusion {
  return (b as Conclusion).status !== undefined &&
    "extraction_order" in b;
}
