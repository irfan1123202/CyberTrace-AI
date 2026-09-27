// CyberTrace AI — Phishing, Spoofing & Email Fraud Detection Engine
// ---------------------------------------------------------------------------
// Implements early and accurate phishing / spoofing / fraud detection with
// structured evidence tiers: OBSERVED FACT, PROBABLE FINDING, UNVERIFIED.
// Does NOT fabricate intelligence or claim physical attacker location.

/**
 * Master phishing / spoofing / fraud detection engine.
 * Aggregates signals from all upstream analysis modules and returns a
 * structured result with IoC list, evidence tiers, MITRE techniques,
 * recommended actions, and a narrative detection summary.
 */
export function runPhishingDetection({
  metadata = {},
  authResults = {},
  hopChain = [],
  protocolAnalysis = {},
  nlpAnalysis = {},
  domainIntelligence = {},
  attributionAssessment = {},
  urls = [],
  attachments = [],
  headers = {},
}) {
  const phishingSignals = detectPhishingSignals({ metadata, urls, nlpAnalysis, authResults, hopChain });
  const spoofingSignals = detectSpoofingSignals({ authResults, protocolAnalysis, domainIntelligence, hopChain });
  const fraudSignals = detectFraudSignals({ nlpAnalysis, metadata, urls, attachments });

  const allSignals = [...phishingSignals, ...spoofingSignals, ...fraudSignals];

  // Weighted threat score
  const criticalCount = allSignals.filter((s) => s.severity === 'CRITICAL').length;
  const highCount = allSignals.filter((s) => s.severity === 'HIGH').length;
  const mediumCount = allSignals.filter((s) => s.severity === 'MEDIUM').length;

  const rawScore = Math.min(
    100,
    criticalCount * 30 + highCount * 18 + mediumCount * 8 + (allSignals.length > 0 ? 5 : 0)
  );

  // Incorporate NLP score and auth failures as modifiers
  const nlpBoost = nlpAnalysis.overallFraudScore ? Math.round(nlpAnalysis.overallFraudScore * 0.4) : 0;
  const spfPenalty = authResults.spf?.status === 'FAIL' ? 15 : 0;
  const dkimPenalty = authResults.dkim?.status === 'FAIL' ? 10 : 0;
  const dmarcPenalty = authResults.dmarc?.status === 'FAIL' ? 10 : 0;
  const authPenalty = spfPenalty + dkimPenalty + dmarcPenalty;

  const overallThreatScore = Math.min(100, Math.round(rawScore * 0.6 + nlpBoost + authPenalty));

  // Classify threat category
  let threatCategory = 'CLEAN / LEGITIMATE';
  let threatSeverity = 'CLEAN';

  const hasCriticalSpoof = spoofingSignals.some((s) => s.severity === 'CRITICAL');
  const hasFinancialFraud = fraudSignals.some((s) => s.category === 'FINANCIAL');
  const hasTorPhish = phishingSignals.some((s) => s.type === 'TOR_ORIGIN_PHISH');
  const hasHighRiskUrl = urls.some((u) => u.riskRating === 'HIGH RISK');

  if (hasCriticalSpoof && hasFinancialFraud) {
    threatCategory = 'BUSINESS EMAIL COMPROMISE (BEC) — FINANCIAL FRAUD';
    threatSeverity = 'CRITICAL';
  } else if (hasTorPhish || hasHighRiskUrl) {
    threatCategory = 'CREDENTIAL PHISHING — SPOOFED BRAND';
    threatSeverity = overallThreatScore >= 70 ? 'CRITICAL' : 'HIGH';
  } else if (spoofingSignals.length > 0 && overallThreatScore >= 50) {
    threatCategory = 'EMAIL SPOOFING — IDENTITY IMPERSONATION';
    threatSeverity = 'HIGH';
  } else if (fraudSignals.length > 0 && overallThreatScore >= 35) {
    threatCategory = 'SOCIAL ENGINEERING / FRAUD ATTEMPT';
    threatSeverity = 'MEDIUM';
  } else if (overallThreatScore >= 20) {
    threatCategory = 'SUSPICIOUS COMMUNICATION — ANALYST REVIEW REQUIRED';
    threatSeverity = 'LOW';
  }

  const iocList = buildIoCList({ hopChain, urls, domainIntelligence, authResults, metadata, attachments });
  const evidenceTiers = buildEvidenceTiers({ authResults, protocolAnalysis, hopChain, urls, domainIntelligence, nlpAnalysis, allSignals });
  const mitreTechniques = buildMitreTechniques({ spoofingSignals, phishingSignals, fraudSignals });
  const recommendedActions = buildRecommendedActions(threatSeverity, overallThreatScore, iocList);
  const detectionSummary = buildDetectionSummary(threatCategory, threatSeverity, overallThreatScore, allSignals, evidenceTiers);

  return {
    overallThreatScore,
    threatCategory,
    threatSeverity,
    phishingSignals,
    spoofingSignals,
    fraudSignals,
    iocList,
    evidenceTiers,
    detectionSummary,
    mitreTechniques,
    recommendedActions,
    signalCount: allSignals.length,
  };
}

// ---------------------------------------------------------------------------
// PHISHING SIGNAL DETECTORS
// ---------------------------------------------------------------------------

export function detectPhishingSignals({ metadata, urls, nlpAnalysis, authResults, hopChain }) {
  const signals = [];
  const originHop = hopChain[hopChain.length - 1];

  const highRiskUrls = urls.filter((u) => u.riskRating === 'HIGH RISK');
  if (highRiskUrls.length > 0) {
    signals.push({
      id: 'PHISH-001',
      type: 'MALICIOUS_URL',
      label: 'Typosquatted / Lookalike URL Detected',
      detail: `Message body contains ${highRiskUrls.length} high-risk URL(s) with domain mimicking patterns: ${highRiskUrls.map((u) => u.domain).join(', ')}`,
      severity: 'CRITICAL',
      category: 'PHISHING',
      evidenceTier: 'OBSERVED_FACT',
      rawEvidence: highRiskUrls.map((u) => u.originalUrl).join('\n'),
    });
  }

  const httpUrls = urls.filter((u) => u.protocol === 'http:');
  if (httpUrls.length > 0 && (nlpAnalysis.credentialTheftScore || 0) > 20) {
    signals.push({
      id: 'PHISH-002',
      type: 'UNENCRYPTED_CREDENTIAL_FORM',
      label: 'HTTP (Unencrypted) Link in Credential-Themed Message',
      detail: `${httpUrls.length} unencrypted HTTP link(s) in a message soliciting credentials. No TLS certificate protection for credential submission.`,
      severity: 'HIGH',
      category: 'PHISHING',
      evidenceTier: 'OBSERVED_FACT',
      rawEvidence: httpUrls.map((u) => u.originalUrl).join('\n'),
    });
  }

  if (originHop?.ipIntelligence?.torIndicator) {
    signals.push({
      id: 'PHISH-003',
      type: 'TOR_ORIGIN_PHISH',
      label: 'Phishing Delivered via Tor Anonymity Network',
      detail: `Earliest observable transmission node (${originHop.sourceIp}) is an active Tor exit relay. The originating party deliberately obfuscated their network identity prior to delivery.`,
      severity: 'CRITICAL',
      category: 'PHISHING',
      evidenceTier: 'OBSERVED_FACT',
      rawEvidence: `IP: ${originHop.sourceIp} | Network: ${originHop.ipIntelligence.networkType} | ASN: ${originHop.ipIntelligence.asn}`,
    });
  }

  if ((nlpAnalysis.credentialTheftScore || 0) >= 50) {
    signals.push({
      id: 'PHISH-004',
      type: 'CREDENTIAL_HARVESTING_LANGUAGE',
      label: 'Credential Solicitation Language Detected',
      detail: `NLP engine identified credential theft cues: ${(nlpAnalysis.credentialMatches || []).slice(0, 4).join(', ')}. Score: ${nlpAnalysis.credentialTheftScore}/100`,
      severity: 'HIGH',
      category: 'PHISHING',
      evidenceTier: 'OBSERVED_FACT',
      rawEvidence: `Matched tokens: ${(nlpAnalysis.credentialMatches || []).join(', ')}`,
    });
  }

  if ((metadata.from || '').includes('@') && urls.length > 0 && (nlpAnalysis.overallFraudScore || 0) >= 40) {
    signals.push({
      id: 'PHISH-005',
      type: 'SUSPICIOUS_SENDER_WITH_PAYLOAD',
      label: 'External Sender with Embedded Payload Links',
      detail: `Sender combined with ${urls.length} embedded payload URL(s) and NLP fraud score of ${nlpAnalysis.overallFraudScore}% constitutes a phishing delivery pattern.`,
      severity: (nlpAnalysis.overallFraudScore || 0) >= 60 ? 'HIGH' : 'MEDIUM',
      category: 'PHISHING',
      evidenceTier: 'PROBABLE_FINDING',
      rawEvidence: `FROM: ${metadata.from} | URLs: ${urls.map((u) => u.domain).join(', ')}`,
    });
  }

  return signals;
}

// ---------------------------------------------------------------------------
// SPOOFING SIGNAL DETECTORS
// ---------------------------------------------------------------------------

export function detectSpoofingSignals({ authResults, protocolAnalysis, domainIntelligence, hopChain }) {
  const signals = [];

  if (authResults.spf?.status === 'FAIL') {
    signals.push({
      id: 'SPOOF-001',
      type: 'SPF_FAIL',
      label: 'SPF Authentication: Hard Failure',
      detail: `The sending IP is not listed in the DNS SPF record published by the claimed sender domain. This is a definitive indicator of unauthorized transmission. Detail: ${authResults.spf.detail}`,
      severity: 'CRITICAL',
      category: 'SPOOFING',
      evidenceTier: 'OBSERVED_FACT',
      rawEvidence: `SPF=${authResults.spf.status}: ${authResults.spf.detail}`,
    });
  }

  if (authResults.dkim?.status === 'FAIL') {
    signals.push({
      id: 'SPOOF-002',
      type: 'DKIM_FAIL',
      label: 'DKIM Cryptographic Signature: Verification Failure',
      detail: `DKIM signature cryptographic verification failed. The message body or headers were tampered with in transit, or the signature was generated by an unauthorized key. Detail: ${authResults.dkim.detail}`,
      severity: 'CRITICAL',
      category: 'SPOOFING',
      evidenceTier: 'OBSERVED_FACT',
      rawEvidence: `DKIM=${authResults.dkim.status}: ${authResults.dkim.detail}`,
    });
  }

  if (authResults.dmarc?.status === 'FAIL') {
    signals.push({
      id: 'SPOOF-003',
      type: 'DMARC_FAIL',
      label: 'DMARC Policy Alignment: Failed',
      detail: `DMARC alignment check failed. Neither SPF nor DKIM passed in alignment with the From: domain. The domain owner's published enforcement policy was violated. Detail: ${authResults.dmarc.detail}`,
      severity: 'HIGH',
      category: 'SPOOFING',
      evidenceTier: 'OBSERVED_FACT',
      rawEvidence: `DMARC=${authResults.dmarc.status}: ${authResults.dmarc.detail}`,
    });
  }

  if (protocolAnalysis.replyToDivergence) {
    signals.push({
      id: 'SPOOF-004',
      type: 'REPLY_TO_HIJACK',
      label: 'Reply-To Thread Hijack Detected',
      detail: `The Reply-To domain (${protocolAnalysis.replyToDomain}) diverges from the From domain (${protocolAnalysis.fromDomain}). Any reply will be silently redirected to the attacker-controlled mailbox.`,
      severity: 'CRITICAL',
      category: 'SPOOFING',
      evidenceTier: 'OBSERVED_FACT',
      rawEvidence: `From domain: ${protocolAnalysis.fromDomain} | Reply-To domain: ${protocolAnalysis.replyToDomain}`,
    });
  }

  if (protocolAnalysis.envelopeMismatch) {
    signals.push({
      id: 'SPOOF-005',
      type: 'ENVELOPE_MISMATCH',
      label: 'SMTP Envelope Sender / Header From Mismatch',
      detail: `The SMTP envelope Return-Path domain (${protocolAnalysis.returnPathDomain}) does not match the displayed From domain (${protocolAnalysis.fromDomain}). Indicates the email was relayed through an unauthorized third-party MTA.`,
      severity: 'HIGH',
      category: 'SPOOFING',
      evidenceTier: 'OBSERVED_FACT',
      rawEvidence: `Return-Path: ${protocolAnalysis.returnPath} | From: ${protocolAnalysis.fromHeader}`,
    });
  }

  if (domainIntelligence.typosquatting?.isLookalike) {
    signals.push({
      id: 'SPOOF-006',
      type: 'TYPOSQUAT_DOMAIN',
      label: 'Lookalike Domain Spoofing Detected',
      detail: `Sender domain "${domainIntelligence.domain}" is a typosquat or homoglyph variant of the legitimate brand "${domainIntelligence.typosquatting.targetedBrand}". Technique: ${domainIntelligence.typosquatting.technique}.`,
      severity: 'CRITICAL',
      category: 'SPOOFING',
      evidenceTier: 'OBSERVED_FACT',
      rawEvidence: `Sender domain: ${domainIntelligence.domain} | Legitimate: ${domainIntelligence.typosquatting.targetedBrand} | Age: ${domainIntelligence.creationDate}`,
    });
  }

  if (domainIntelligence.domainAgeDays !== undefined && domainIntelligence.domainAgeDays < 30) {
    signals.push({
      id: 'SPOOF-007',
      type: 'NEWLY_REGISTERED_DOMAIN',
      label: 'Newly Registered Sender Domain (High-Risk)',
      detail: `Sender domain "${domainIntelligence.domain}" was registered approximately ${domainIntelligence.domainAgeDays} day(s) ago. Newly registered domains are a common infrastructure characteristic of targeted spear-phishing campaigns.`,
      severity: domainIntelligence.domainAgeDays < 7 ? 'CRITICAL' : 'HIGH',
      category: 'SPOOFING',
      evidenceTier: 'OBSERVED_FACT',
      rawEvidence: `Domain: ${domainIntelligence.domain} | Age: ${domainIntelligence.domainAgeDays} days | Registrar: ${domainIntelligence.registrar}`,
    });
  }

  const fromLower = (protocolAnalysis.fromHeader || '').toLowerCase();
  const executiveTitles = ['cfo', 'ceo', 'director', 'vice president', 'vp', 'president', 'chairman'];
  const hasExecutiveTitle = executiveTitles.some((t) => fromLower.includes(t));
  if (hasExecutiveTitle && authResults.spf?.status !== 'PASS') {
    signals.push({
      id: 'SPOOF-008',
      type: 'EXECUTIVE_DISPLAY_NAME_IMPERSONATION',
      label: 'Executive Identity Display Name Impersonation',
      detail: `The From display name appears to impersonate an executive or authority figure while SPF authentication did not pass. This is characteristic of Business Email Compromise (BEC) display name spoofing.`,
      severity: 'HIGH',
      category: 'SPOOFING',
      evidenceTier: 'PROBABLE_FINDING',
      rawEvidence: `From: ${protocolAnalysis.fromHeader} | SPF: ${authResults.spf?.status}`,
    });
  }

  return signals;
}

// ---------------------------------------------------------------------------
// FRAUD SIGNAL DETECTORS
// ---------------------------------------------------------------------------

export function detectFraudSignals({ nlpAnalysis, metadata, urls, attachments }) {
  const signals = [];

  if ((nlpAnalysis.financialRiskScore || 0) >= 40) {
    signals.push({
      id: 'FRAUD-001',
      type: 'PAYMENT_DIVERSION',
      label: 'Financial Diversion / Wire Transfer Mandate',
      detail: `Message contains ${nlpAnalysis.financialMatches?.length || 0} financial directive cue(s): ${(nlpAnalysis.financialMatches || []).slice(0, 5).join(', ')}. This is the primary vector for Business Email Compromise wire fraud.`,
      severity: (nlpAnalysis.financialRiskScore || 0) >= 70 ? 'CRITICAL' : 'HIGH',
      category: 'FINANCIAL',
      evidenceTier: 'OBSERVED_FACT',
      rawEvidence: `Financial keywords: ${(nlpAnalysis.financialMatches || []).join(', ')} | Score: ${nlpAnalysis.financialRiskScore}/100`,
    });
  }

  if ((nlpAnalysis.urgencyScore || 0) >= 40) {
    signals.push({
      id: 'FRAUD-002',
      type: 'ARTIFICIAL_URGENCY',
      label: 'Artificial Deadline / Temporal Coercion',
      detail: `Message imposes artificial time pressure using ${nlpAnalysis.urgencyMatches?.length || 0} urgency trigger(s): ${(nlpAnalysis.urgencyMatches || []).slice(0, 4).join(', ')}. Designed to prevent recipient from verifying with supervisors.`,
      severity: (nlpAnalysis.urgencyScore || 0) >= 60 ? 'HIGH' : 'MEDIUM',
      category: 'SOCIAL_ENGINEERING',
      evidenceTier: 'OBSERVED_FACT',
      rawEvidence: `Urgency keywords: ${(nlpAnalysis.urgencyMatches || []).join(', ')} | Score: ${nlpAnalysis.urgencyScore}/100`,
    });
  }

  if ((nlpAnalysis.coercionScore || 0) >= 40) {
    signals.push({
      id: 'FRAUD-003',
      type: 'AUTHORITY_COERCION',
      label: 'Executive Authority & Confidentiality Coercion',
      detail: `Message exploits authority and confidentiality constructs: ${(nlpAnalysis.authorityMatches || []).slice(0, 4).join(', ')}. Classic BEC social engineering to prevent victims from consulting colleagues.`,
      severity: (nlpAnalysis.coercionScore || 0) >= 60 ? 'HIGH' : 'MEDIUM',
      category: 'SOCIAL_ENGINEERING',
      evidenceTier: 'OBSERVED_FACT',
      rawEvidence: `Authority/coercion keywords: ${(nlpAnalysis.authorityMatches || []).join(', ')} | Score: ${nlpAnalysis.coercionScore}/100`,
    });
  }

  const dangerousExts = ['exe', 'js', 'vbs', 'bat', 'ps1', 'hta', 'scr', 'lnk', 'iso', 'doc', 'xls', 'ppt'];
  const dangerousAttachments = attachments.filter((a) => dangerousExts.includes((a.extension || '').toLowerCase()));
  if (dangerousAttachments.length > 0) {
    signals.push({
      id: 'FRAUD-004',
      type: 'MALICIOUS_ATTACHMENT',
      label: 'Potentially Malicious Attachment File Type',
      detail: `${dangerousAttachments.length} attachment(s) with high-risk extension(s) detected: ${dangerousAttachments.map((a) => `${a.filename} (.${a.extension})`).join(', ')}. Sandbox detonation required before accessing.`,
      severity: 'CRITICAL',
      category: 'MALWARE',
      evidenceTier: 'PROBABLE_FINDING',
      rawEvidence: dangerousAttachments.map((a) => `${a.filename} | SHA-256: ${a.sha256}`).join('\n'),
    });
  }

  const hasHighRiskUrl = urls.some((u) => u.riskRating === 'HIGH RISK');
  const hasFinancialRisk = (nlpAnalysis.financialRiskScore || 0) >= 30;
  const hasUrgency = (nlpAnalysis.urgencyScore || 0) >= 30;
  if (hasHighRiskUrl && hasFinancialRisk && hasUrgency) {
    signals.push({
      id: 'FRAUD-005',
      type: 'MULTI_VECTOR_ATTACK',
      label: 'Multi-Vector Attack: Payload + Financial Directive + Urgency',
      detail: `This message simultaneously deploys three attack vectors: (1) malicious payload URL(s), (2) financial diversion directive, and (3) urgency coercion. Consistent with advanced targeted BEC campaigns.`,
      severity: 'CRITICAL',
      category: 'COMBINED',
      evidenceTier: 'PROBABLE_FINDING',
      rawEvidence: `High-risk URLs: ${urls.filter((u) => u.riskRating === 'HIGH RISK').map((u) => u.domain).join(', ')} | Financial score: ${nlpAnalysis.financialRiskScore} | Urgency score: ${nlpAnalysis.urgencyScore}`,
    });
  }

  return signals;
}

// ---------------------------------------------------------------------------
// IOC LIST BUILDER
// ---------------------------------------------------------------------------

export function buildIoCList({ hopChain, urls, domainIntelligence, authResults, metadata, attachments }) {
  const iocs = [];

  hopChain.forEach((hop) => {
    if (hop.sourceIp && hop.sourceIp !== 'UNKNOWN') {
      iocs.push({
        type: 'IP_ADDRESS',
        value: hop.sourceIp,
        context: `${hop.role || 'Relay'} — ${hop.ipIntelligence?.networkType || 'Unknown Network'} (${hop.ipIntelligence?.isp || 'Unknown ISP'})`,
        riskLevel: hop.trustLevel === 'UNTRUSTED' ? 'HIGH' : hop.trustLevel === 'SUSPICIOUS' ? 'MEDIUM' : 'LOW',
        asn: hop.ipIntelligence?.asn || 'UNKNOWN',
        geo: `${hop.ipIntelligence?.city && hop.ipIntelligence.city !== 'UNKNOWN' ? hop.ipIntelligence.city + ', ' : ''}${hop.ipIntelligence?.country || 'Unknown'}`,
        tor: hop.ipIntelligence?.torIndicator || false,
        evidenceTier: 'OBSERVED_FACT',
      });
    }
  });

  if (domainIntelligence.domain && domainIntelligence.domain !== 'UNKNOWN') {
    iocs.push({
      type: 'DOMAIN',
      value: domainIntelligence.domain,
      context: `Sender domain | Registrar: ${domainIntelligence.registrar || 'Unknown'} | Age: ${domainIntelligence.creationDate || 'Unknown'}`,
      riskLevel: (domainIntelligence.ageRiskLevel || '').includes('CRITICAL')
        ? 'CRITICAL'
        : domainIntelligence.typosquatting?.isLookalike
        ? 'HIGH'
        : 'MEDIUM',
      typosquat: domainIntelligence.typosquatting?.isLookalike || false,
      targetedBrand: domainIntelligence.typosquatting?.targetedBrand || 'N/A',
      evidenceTier: 'OBSERVED_FACT',
    });
  }

  urls.forEach((url) => {
    iocs.push({
      type: 'URL',
      value: url.originalUrl,
      context: `Domain: ${url.domain} | TLS: ${url.tlsCertificate || 'Unknown'} | Reputation: ${url.reputationSignal || 'Unknown'}`,
      riskLevel: url.riskRating === 'HIGH RISK' ? 'CRITICAL' : 'MEDIUM',
      domain: url.domain,
      evidenceTier: 'OBSERVED_FACT',
    });
  });

  attachments.forEach((att) => {
    iocs.push({
      type: 'FILE_HASH',
      value: att.sha256 || 'N/A',
      context: `File: ${att.filename} | Type: ${att.mimeType} | Size: ~${Math.round((att.sizeBytes || 0) / 1024)} KB`,
      riskLevel: ['exe', 'js', 'vbs', 'doc', 'xls'].includes((att.extension || '').toLowerCase()) ? 'HIGH' : 'MEDIUM',
      filename: att.filename,
      evidenceTier: 'OBSERVED_FACT',
    });
  });

  if (metadata.from && metadata.from !== 'Unknown Sender') {
    const emailMatch = metadata.from.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
    if (emailMatch) {
      iocs.push({
        type: 'EMAIL_ADDRESS',
        value: emailMatch[0],
        context: `Sender claimed identity (UNVERIFIED — SPF: ${authResults.spf?.status || 'UNKNOWN'})`,
        riskLevel: authResults.spf?.status === 'FAIL' ? 'HIGH' : 'LOW',
        evidenceTier: authResults.spf?.status === 'FAIL' ? 'PROBABLE_FINDING' : 'UNVERIFIED',
      });
    }
  }

  return iocs;
}

// ---------------------------------------------------------------------------
// EVIDENCE TIER BUILDER
// ---------------------------------------------------------------------------

export function buildEvidenceTiers({ authResults, protocolAnalysis, hopChain, urls, domainIntelligence, nlpAnalysis, allSignals }) {
  const observedFacts = [];
  const probableFindings = [];
  const unverified = [];

  hopChain.forEach((hop) => {
    observedFacts.push(
      `RFC-5322 Received header records transmission through ${hop.fromHost || hop.sourceIp} [${hop.sourceIp}] at ${hop.timestamp} (${hop.timezone || 'UTC'})`
    );
  });

  if (authResults.spf?.status && authResults.spf.status !== 'UNKNOWN') {
    observedFacts.push(`Authentication-Results header records SPF=${authResults.spf.status}: ${authResults.spf.detail}`);
  }
  if (authResults.dkim?.status && authResults.dkim.status !== 'UNKNOWN') {
    observedFacts.push(`Authentication-Results header records DKIM=${authResults.dkim.status}: ${authResults.dkim.detail}`);
  }
  if (authResults.dmarc?.status && authResults.dmarc.status !== 'UNKNOWN') {
    observedFacts.push(`Authentication-Results header records DMARC=${authResults.dmarc.status}: ${authResults.dmarc.detail}`);
  }
  if (protocolAnalysis.envelopeMismatch) {
    observedFacts.push(`SMTP Return-Path domain (${protocolAnalysis.returnPathDomain}) diverges from header From domain (${protocolAnalysis.fromDomain}) — envelope mismatch confirmed`);
  }
  if (protocolAnalysis.replyToDivergence) {
    observedFacts.push(`Reply-To header redirects to ${protocolAnalysis.replyToDomain}, a different domain from the displayed sender ${protocolAnalysis.fromDomain}`);
  }
  if (domainIntelligence.typosquatting?.isLookalike) {
    observedFacts.push(`Sender domain "${domainIntelligence.domain}" exhibits lookalike characteristics vs. "${domainIntelligence.typosquatting.targetedBrand}" — ${domainIntelligence.typosquatting.technique}`);
  }
  urls.forEach((url) => {
    observedFacts.push(`URL extracted from message body: ${url.originalUrl} (domain: ${url.domain})`);
  });

  const originHop = hopChain[hopChain.length - 1];
  if (originHop?.trustLevel === 'UNTRUSTED') {
    probableFindings.push(
      `The earliest observable relay node (${originHop.sourceIp}) is not authorized by the sender domain's SPF policy. This probably indicates the email originated from infrastructure not controlled by the legitimate domain owner.`
    );
  }
  if (originHop?.ipIntelligence?.torIndicator) {
    probableFindings.push(
      `The origin IP (${originHop.sourceIp}) is an active Tor exit relay. The sender probably used Tor to conceal their true network location before delivering this message.`
    );
  }
  if ((nlpAnalysis.overallFraudScore || 0) >= 50) {
    probableFindings.push(
      `Linguistic analysis identifies a ${nlpAnalysis.overallFraudScore}% probability of deceptive intent based on social engineering keyword patterns. This assessment is based on behavioral indicators, not definitive technical authentication.`
    );
  }
  if (domainIntelligence.domainAgeDays !== undefined && domainIntelligence.domainAgeDays < 30) {
    probableFindings.push(
      `The sender domain was registered approximately ${domainIntelligence.domainAgeDays} days ago. Newly registered domains are frequently used in targeted email fraud campaigns. This does not conclusively prove malicious intent.`
    );
  }
  allSignals
    .filter((s) => s.evidenceTier === 'PROBABLE_FINDING')
    .forEach((s) => probableFindings.push(`[${s.id}] ${s.label}: ${s.detail}`));

  unverified.push(
    `Physical location of the sender cannot be determined from IP geolocation alone. IP geolocation identifies network infrastructure endpoints, not the attacker's physical position.`
  );
  unverified.push(
    `True identity of the sender cannot be confirmed from header analysis alone. Display names and From addresses can be spoofed without modifying technical headers.`
  );
  if (urls.length > 0) {
    unverified.push(
      `Destination content of extracted URLs has not been verified. Sandbox analysis required to confirm redirect chains and payload detonation behavior.`
    );
  }

  return { observedFacts, probableFindings, unverified };
}

// ---------------------------------------------------------------------------
// MITRE ATT&CK TECHNIQUES
// ---------------------------------------------------------------------------

export function buildMitreTechniques({ spoofingSignals, phishingSignals, fraudSignals }) {
  const techniques = [];

  if (spoofingSignals.some((s) => s.type === 'SPF_FAIL' || s.type === 'DKIM_FAIL')) {
    techniques.push({
      id: 'T1566.001',
      name: 'Spearphishing Attachment / Spoofed Sender',
      tactic: 'Initial Access',
      description: 'Adversary forged sender authentication headers to bypass organizational mail filters.',
      confidence: 'HIGH',
    });
  }
  if (spoofingSignals.some((s) => s.type === 'TYPOSQUAT_DOMAIN')) {
    techniques.push({
      id: 'T1583.001',
      name: 'Acquire Infrastructure: Domains',
      tactic: 'Resource Development',
      description: 'Adversary registered a lookalike domain to impersonate a trusted organization.',
      confidence: 'HIGH',
    });
  }
  if (phishingSignals.some((s) => s.type === 'TOR_ORIGIN_PHISH')) {
    techniques.push({
      id: 'T1090.003',
      name: 'Proxy: Multi-hop Proxy (Tor)',
      tactic: 'Command & Control',
      description: 'Adversary routed email delivery through Tor exit relay to obfuscate origin.',
      confidence: 'HIGH',
    });
  }
  if (fraudSignals.some((s) => s.type === 'PAYMENT_DIVERSION')) {
    techniques.push({
      id: 'T1657',
      name: 'Financial Theft: Wire Transfer Fraud',
      tactic: 'Impact',
      description: 'Adversary directed finance personnel to initiate unauthorized wire transfer to attacker-controlled account.',
      confidence: 'HIGH',
    });
  }
  if (fraudSignals.some((s) => s.type === 'AUTHORITY_COERCION' || s.type === 'ARTIFICIAL_URGENCY')) {
    techniques.push({
      id: 'T1598',
      name: 'Phishing for Information',
      tactic: 'Reconnaissance',
      description: 'Adversary exploited authority and urgency constructs to suppress verification behavior.',
      confidence: 'MEDIUM',
    });
  }
  if (spoofingSignals.some((s) => s.type === 'REPLY_TO_HIJACK')) {
    techniques.push({
      id: 'T1534',
      name: 'Internal Spearphishing: Thread Hijack',
      tactic: 'Lateral Movement',
      description: 'Reply-To header redirects all responses to attacker-controlled mailbox, enabling conversation hijacking.',
      confidence: 'HIGH',
    });
  }

  return techniques;
}

// ---------------------------------------------------------------------------
// RECOMMENDED ACTIONS
// ---------------------------------------------------------------------------

export function buildRecommendedActions(severity, score, iocList) {
  const actions = [];
  const ipIocs = iocList.filter((i) => i.type === 'IP_ADDRESS').map((i) => i.value).join(', ');
  const domainIocs = iocList.filter((i) => i.type === 'DOMAIN' && i.riskLevel !== 'LOW');

  if (severity === 'CRITICAL') {
    actions.push('IMMEDIATE: Quarantine message from all recipient mailboxes across tenant. Do not allow any user interaction.');
    if (ipIocs) actions.push(`IMMEDIATE: Block originating IP(s) at perimeter firewall and SIEM: ${ipIocs}`);
    actions.push('IMMEDIATE: Issue emergency advisory to Finance / Executive Office — disregard all instructions in this email.');
    actions.push('URGENT: Reset credentials of any recipient who clicked links or replied. Audit all active SSO sessions.');
    actions.push('URGENT: Submit email headers and IoCs to threat intelligence platforms (VirusTotal, AbuseIPDB, Cisco Talos).');
    actions.push('WITHIN 24H: File formal incident report with CISO and Legal. Preserve all evidence with chain of custody.');
    actions.push('WITHIN 24H: Notify relevant banking institutions if wire transfer requests were issued.');
  } else if (severity === 'HIGH') {
    actions.push('PRIORITY: Hold message in administrative quarantine queue. Do not deliver to recipient.');
    actions.push('PRIORITY: Verify authenticity with purported sender via known-good out-of-band contact (phone / directory).');
    actions.push('REVIEW: Analyze all hyperlinks in isolated sandbox environment before allowing access.');
    actions.push('MONITOR: Add sender domain and IP addresses to organizational watch list for 30 days.');
    actions.push('DOCUMENT: Record incident details in SIEM / ticketing system for correlation.');
  } else if (severity === 'MEDIUM') {
    actions.push('REVIEW: Flag message for secondary analyst review before delivery.');
    actions.push('VERIFY: Confirm sender identity through out-of-band verification channel.');
    actions.push('LOG: Record suspicious signals in security log for trend analysis.');
  } else {
    actions.push('MONITOR: No immediate action required. Log and continue monitoring.');
    actions.push('AWARENESS: Consider user awareness training if similar patterns emerge.');
  }

  if (domainIocs.length > 0) {
    actions.push(`DNS BLOCK: Add domains to organizational blocklist: ${domainIocs.map((i) => i.value).join(', ')}`);
  }

  return actions;
}

// ---------------------------------------------------------------------------
// DETECTION SUMMARY NARRATIVE
// ---------------------------------------------------------------------------

export function buildDetectionSummary(threatCategory, severity, score, signals, evidenceTiers) {
  const factCount = evidenceTiers.observedFacts.length;
  const probableCount = evidenceTiers.probableFindings.length;

  if (severity === 'CLEAN') {
    return `Forensic analysis identified no high-confidence deception indicators. All authentication checks (SPF, DKIM, DMARC) returned expected results. Linguistic analysis found no social engineering patterns. This communication appears consistent with legitimate institutional correspondence. Confidence is based on ${factCount} observed facts from cryptographic header analysis.`;
  }

  const categories = [...new Set(signals.map((s) => s.category))].join(', ');
  const signalSummary = signals.length > 0
    ? `Detection engine identified ${signals.length} threat signal(s) across ${categories} categories. `
    : '';

  return `${signalSummary}Overall threat score: ${score}/100 (${severity}). Classification: ${threatCategory}. Analysis is supported by ${factCount} observed fact(s) directly extracted from RFC-5322 message headers and ${probableCount} probable finding(s) derived from cross-signal correlation. IP geolocation data identifies network infrastructure endpoints and does not represent the physical location of the threat actor. All conclusions should be reviewed by a qualified security analyst before enforcement action.`;
}
