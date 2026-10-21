import { desc, eq } from "drizzle-orm";
import { db } from "./index.ts";
import {
  iocRecordsTable,
  rbacAuditLogs,
  soarExecutionLogs,
  soarPlaybooks,
  trainingCorpus,
  users,
} from "./schema.ts";

export async function getOrCreateUser(
  uid: string,
  email: string,
  fullName = "Lead SOC Analyst"
) {
  try {
    const result = await db
      .insert(users)
      .values({
        uid,
        email,
        fullName,
        role: "SOC Lead",
      })
      .onConflictDoUpdate({
        target: users.uid,
        set: {
          email,
        },
      })
      .returning();
    return result[0];
  } catch (error) {
    console.error("Database user upsert failed:", error);
    throw new Error("Failed to synchronize user profile.", { cause: error });
  }
}

export async function updateUserRoleInDb(uid: string, newRole: string) {
  try {
    const updated = await db
      .update(users)
      .set({ role: newRole })
      .where(eq(users.uid, uid))
      .returning();
    return updated[0] || null;
  } catch (error) {
    console.error("Database role update failed:", error);
    throw new Error("Failed to update RBAC role.", { cause: error });
  }
}

export async function insertAuditLog(entry: {
  userUid: string;
  userEmail: string;
  userRole: string;
  action: string;
  targetIoc: string;
  details: string;
}) {
  try {
    const inserted = await db.insert(rbacAuditLogs).values(entry).returning();
    return inserted[0];
  } catch (error) {
    console.error("Audit log insert failed:", error);
    throw new Error("Failed to record RBAC audit log.", { cause: error });
  }
}

export async function getRecentAuditLogs(limit = 40) {
  try {
    return await db
      .select()
      .from(rbacAuditLogs)
      .orderBy(desc(rbacAuditLogs.id))
      .limit(limit);
  } catch (error) {
    console.error("Audit logs fetch failed:", error);
    throw new Error("Failed to fetch RBAC audit logs.", { cause: error });
  }
}

export async function upsertIocRecordToDb(rec: {
  ioc_value: string;
  ioc_type?: string;
  threat_type?: string;
  tags?: string[];
  source_feeds?: string[];
  status?: string;
  sighting_count?: number;
  feed_confidence?: number;
  ml_malicious_prob?: number;
  is_anomaly?: boolean;
  risk_score?: number;
  triage_status?: string;
  first_seen?: string;
  last_seen?: string;
}) {
  try {
    const tagsStr = JSON.stringify(rec.tags || []);
    const feedsStr = JSON.stringify(rec.source_feeds || []);
    const probStr = String(rec.ml_malicious_prob ?? 0.85);
    const anomalyInt = rec.is_anomaly ? 1 : 0;
    const nowIso = new Date().toISOString();

    const result = await db
      .insert(iocRecordsTable)
      .values({
        iocValue: rec.ioc_value,
        iocType: rec.ioc_type || "url",
        threatType: rec.threat_type || "malware_download",
        tagsJson: tagsStr,
        sourceFeedsJson: feedsStr,
        status: rec.status || "online",
        sightingCount: rec.sighting_count || 1,
        feedConfidence: Math.round(rec.feed_confidence || 82),
        mlMaliciousProb: probStr,
        isAnomaly: anomalyInt,
        riskScore: Math.round(rec.risk_score || 80),
        triageStatus: rec.triage_status || "needs_review",
        firstSeen: rec.first_seen || nowIso,
        lastSeen: rec.last_seen || nowIso,
      })
      .onConflictDoUpdate({
        target: iocRecordsTable.iocValue,
        set: {
          tagsJson: tagsStr,
          sourceFeedsJson: feedsStr,
          status: rec.status || "online",
          sightingCount: rec.sighting_count || 1,
          feedConfidence: Math.round(rec.feed_confidence || 82),
          mlMaliciousProb: probStr,
          isAnomaly: anomalyInt,
          riskScore: Math.round(rec.risk_score || 80),
          triageStatus: rec.triage_status || "needs_review",
          lastSeen: rec.last_seen || nowIso,
        },
      })
      .returning();

    return result[0];
  } catch (error) {
    console.error("IOC record upsert failed:", error);
    throw new Error("Failed to persist IOC record.", { cause: error });
  }
}

export async function upsertTrainingSampleToDb(sample: {
  iocValue: string;
  label: number;
  source: string;
  addedByEmail: string;
}) {
  try {
    const result = await db
      .insert(trainingCorpus)
      .values({
        iocValue: sample.iocValue,
        label: sample.label,
        source: sample.source,
        addedByEmail: sample.addedByEmail,
      })
      .onConflictDoUpdate({
        target: trainingCorpus.iocValue,
        set: {
          label: sample.label,
          source: sample.source,
          addedByEmail: sample.addedByEmail,
        },
      })
      .returning();
    return result[0];
  } catch (error) {
    console.error("Training corpus upsert failed:", error);
    throw new Error("Failed to persist training sample.", { cause: error });
  }
}

export async function getPersistedTrainingSamples() {
  try {
    return await db
      .select()
      .from(trainingCorpus)
      .orderBy(desc(trainingCorpus.id))
      .limit(200);
  } catch (error) {
    console.error("Training corpus query failed:", error);
    throw new Error("Failed to load training samples.", { cause: error });
  }
}

const DEFAULT_PLAYBOOKS = [
  {
    name: "SOC Tier-1 Critical Alert Channel",
    channel: "slack",
    webhookUrl: "https://hooks.slack.com/services/T00SOC/B00THREATOPS/critical-ioc-stream",
    minRiskThreshold: 85,
    enabled: 1,
  },
  {
    name: "PagerDuty High-Severity Incident Trigger",
    channel: "pagerduty",
    webhookUrl: "https://events.pagerduty.com/v2/enqueue",
    minRiskThreshold: 90,
    enabled: 1,
  },
  {
    name: "Cloudflare Enterprise WAF IP/URL Blocklist",
    channel: "cloudflare_waf",
    webhookUrl: "https://api.cloudflare.com/client/v4/accounts/soc/rules/lists/block",
    minRiskThreshold: 85,
    enabled: 1,
  },
  {
    name: "Google Workspace Gmail Phishing Quarantine",
    channel: "gmail_quarantine",
    webhookUrl: "https://admin.googleapis.com/admin/directory/v1/quarantine/phishing",
    minRiskThreshold: 85,
    enabled: 1,
  },
];

export async function getOrSeedSoarPlaybooks() {
  try {
    const existing = await db.select().from(soarPlaybooks).orderBy(soarPlaybooks.id);
    if (existing.length > 0) return existing;

    const inserted = await db
      .insert(soarPlaybooks)
      .values(DEFAULT_PLAYBOOKS)
      .returning();
    return inserted;
  } catch (error) {
    console.error("SOAR playbooks fetch/seed failed:", error);
    throw new Error("Failed to load SOAR playbooks.", { cause: error });
  }
}

export async function createSoarPlaybookInDb(payload: {
  name: string;
  channel: string;
  webhookUrl: string;
  minRiskThreshold: number;
}) {
  try {
    const inserted = await db
      .insert(soarPlaybooks)
      .values({
        name: payload.name,
        channel: payload.channel,
        webhookUrl: payload.webhookUrl,
        minRiskThreshold: payload.minRiskThreshold,
        enabled: 1,
      })
      .returning();
    return inserted[0];
  } catch (error) {
    console.error("Create SOAR playbook failed:", error);
    throw new Error("Failed to create SOAR playbook.", { cause: error });
  }
}

export async function toggleSoarPlaybookInDb(id: number, enabled: number) {
  try {
    const updated = await db
      .update(soarPlaybooks)
      .set({ enabled })
      .where(eq(soarPlaybooks.id, id))
      .returning();
    return updated[0] || null;
  } catch (error) {
    console.error("Toggle SOAR playbook failed:", error);
    throw new Error("Failed to update SOAR playbook.", { cause: error });
  }
}

export async function recordSoarWebhookExecutionInDb(
  playbook: { id: number; name: string; channel: string; triggerCount: number },
  iocValue: string,
  riskScore: number,
  deliveryStatus: string,
  payloadPreview: string
) {
  try {
    const nowIso = new Date().toISOString();
    await db
      .update(soarPlaybooks)
      .set({
        triggerCount: (playbook.triggerCount || 0) + 1,
        lastTriggeredAt: nowIso,
      })
      .where(eq(soarPlaybooks.id, playbook.id));

    const inserted = await db
      .insert(soarExecutionLogs)
      .values({
        playbookName: playbook.name,
        channel: playbook.channel,
        iocValue,
        riskScore,
        deliveryStatus,
        payloadPreview,
      })
      .returning();
    return inserted[0];
  } catch (error) {
    console.error("Record SOAR execution failed:", error);
    throw new Error("Failed to record SOAR webhook execution.", { cause: error });
  }
}

export async function getRecentSoarExecutions(limit = 25) {
  try {
    return await db
      .select()
      .from(soarExecutionLogs)
      .orderBy(desc(soarExecutionLogs.id))
      .limit(limit);
  } catch (error) {
    console.error("Fetch SOAR executions failed:", error);
    throw new Error("Failed to fetch SOAR execution history.", { cause: error });
  }
}
