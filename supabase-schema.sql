-- =========================================================
-- CyberTrace AI — Supabase PostgreSQL Schema (SIH 2026)
-- Free Cloud Database Setup for Team Syndicate (PS 26106)
-- =========================================================

-- 1. Enable UUID Extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 2. Drop existing tables if rebuilding (clean start)
-- DROP TABLE IF EXISTS forensic_reports CASCADE;
-- DROP TABLE IF EXISTS cases CASCADE;
-- DROP TABLE IF EXISTS analysts CASCADE;

-- 3. Analysts Table (SOC Personnel & Investigators)
CREATE TABLE IF NOT EXISTS analysts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role TEXT DEFAULT 'Tier-2 SOC Analyst',
    clearance VARCHAR(20) DEFAULT 'CLR-L2',
    shift VARCHAR(30) DEFAULT 'Shift A',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Investigation Cases Table (Email Threat Incidents)
CREATE TABLE IF NOT EXISTS cases (
    id VARCHAR(50) PRIMARY KEY,
    subject TEXT NOT NULL,
    from_addr TEXT NOT NULL,
    display_from TEXT NOT NULL,
    to_addr TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    status VARCHAR(30) DEFAULT 'pending', -- pending, escalated, cleared
    priority VARCHAR(30) DEFAULT 'medium', -- critical, high, medium, low
    preview TEXT,
    header_sample VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 5. Forensic Reports & Evidence Hash Chains (NIST SP 800-86)
CREATE TABLE IF NOT EXISTS forensic_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id VARCHAR(50) REFERENCES cases(id) ON DELETE CASCADE,
    evidence_hash TEXT NOT NULL,
    verdict JSONB,
    hops JSONB,
    geo_origin JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 6. Enable Row Level Security (RLS) with Public Demo Access
ALTER TABLE analysts ENABLE ROW LEVEL SECURITY;
ALTER TABLE cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE forensic_reports ENABLE ROW LEVEL SECURITY;

-- Allow anonymous read & write for prototype / hackathon frontend
CREATE POLICY "Allow anon read analysts" ON analysts FOR SELECT USING (true);
CREATE POLICY "Allow anon insert analysts" ON analysts FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow anon read cases" ON cases FOR SELECT USING (true);
CREATE POLICY "Allow anon write cases" ON cases FOR ALL USING (true);

CREATE POLICY "Allow anon read reports" ON forensic_reports FOR SELECT USING (true);
CREATE POLICY "Allow anon write reports" ON forensic_reports FOR ALL USING (true);

-- 7. Seed Initial Realistic SOC Triage Cases (SIH 2026 Scenarios)
INSERT INTO cases (id, subject, from_addr, display_from, to_addr, received_at, status, priority, preview, header_sample)
VALUES 
(
    'CASE-2026-0417',
    'URGENT: Wire Transfer Approval Needed — CFO Office',
    'r.iyer@annapoorna-edu.in',
    'Rajesh Iyer <r.iyer@annapoorna-edu.in>',
    'finance-team@annapoorna.edu.in',
    '2026-09-24T09:12:00+05:30',
    'pending',
    'critical',
    'Please process the attached vendor payment before EOD, this is time-sensitive and confidential...',
    'HDR_BEC_SPOOF_01'
),
(
    'CASE-2026-0418',
    'Your account will be suspended — verify now',
    'security-alert@paypa1-support.com',
    'PayPal Security <security-alert@paypa1-support.com>',
    'accounts@annapoorna.edu.in',
    '2026-09-24T08:47:00+05:30',
    'pending',
    'high',
    'We noticed unusual activity on your account. Click below to verify your identity within 24 hours...',
    'HDR_PHISH_TOR_02'
),
(
    'CASE-2026-0419',
    'Re: Semester Fee Structure 2026-27',
    'registrar@annapoorna.edu.in',
    'Registrar Office <registrar@annapoorna.edu.in>',
    'students-list@annapoorna.edu.in',
    '2026-09-24T07:30:00+05:30',
    'cleared',
    'low',
    'Attached is the revised fee structure approved by the finance committee for AY 2026-27...',
    'HDR_LEGIT_01'
),
(
    'CASE-2026-0420',
    'Invoice #INV-88213 Payment Overdue',
    'billing@vendor-supplyco.net',
    'SupplyCo Billing <billing@vendor-supplyco.net>',
    'procurement@annapoorna.edu.in',
    '2026-09-23T18:05:00+05:30',
    'pending',
    'medium',
    'Your payment for the attached invoice is 14 days overdue. Immediate settlement is required to avoid...',
    'HDR_PHISH_PROXY_03'
),
(
    'CASE-2026-0421',
    'Faculty Research Grant — Action Required',
    'grants@aicte-portal-gov.org',
    'AICTE Grants Cell <grants@aicte-portal-gov.org>',
    'dean-research@annapoorna.edu.in',
    '2026-09-23T16:22:00+05:30',
    'escalated',
    'high',
    'Notification regarding project renewal under the AICTE Collaborative Research Scheme 2026...',
    'HDR_PHISH_GOV_SPOOF_04'
)
ON CONFLICT (id) DO NOTHING;
