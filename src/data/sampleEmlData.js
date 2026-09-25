// Realistic RFC-5322 MIME .eml samples for isolated defensive analysis.

export const SAMPLE_BEC_WIRE_TRANSFER = `Received: by mail.annapoorna.edu.in (Postfix, from userid 1001)
	id 4Z9P110M90; Thu, 24 Sep 2026 09:12:00 +0530 (IST)
X-Spam-Checker-Version: SpamAssassin 3.4.6 (2021-04-09) on mx.annapoorna.edu.in
X-Spam-Level: *******
X-Spam-Status: Yes, score=7.4 required=5.0 tests=FORGED_SPF,DKIM_INVALID,
	URGENT_BIZ_LANG,FREEMAIL_FORGED_REPLYTO,HTML_MESSAGE autolearn=no
Authentication-Results: mx.annapoorna.edu.in;
	dkim=fail reason="signature verification failed" header.d=annapoorna-edu.in;
	spf=fail (mx.annapoorna.edu.in: domain of r.iyer@annapoorna-edu.in does not designate 154.16.63.102 as permitted sender) smtp.mailfrom=r.iyer@annapoorna-edu.in;
	dmarc=fail (p=quarantine dis=none) header.from=annapoorna-edu.in
Received: from smtp-relay-04.outbound-corp.net (smtp-relay-04.outbound-corp.net [198.51.100.77])
	by mail.annapoorna.edu.in (Postfix) with ESMTPS id 3L0219M87
	for <finance-team@annapoorna.edu.in>; Thu, 24 Sep 2026 09:11:48 +0530 (IST)
Received: from mx1.freemailer-gw.com (mx1.freemailer-gw.com [154.16.63.102])
	by smtp-relay-04.outbound-corp.net (Postfix) with ESMTP id 88A9F102B
	for <finance-team@annapoorna.edu.in>; Thu, 24 Sep 2026 03:41:40 +0000 (UTC)
Received: from [10.0.4.12] (helo=workstation-cfo-win11.local)
	by mx1.freemailer-gw.com with ESMTPA id B2901CA8891;
	Thu, 24 Sep 2026 05:40:15 +0200
Message-ID: <20260924034015.B2901CA8891@freemailer-gw.com>
Date: Thu, 24 Sep 2026 09:10:00 +0530
From: "Rajesh Iyer" <r.iyer@annapoorna-edu.in>
Reply-To: "Rajesh Iyer - Executive Office" <r.iyer@annapoorna-edu.in>
To: <finance-team@annapoorna.edu.in>
Subject: URGENT: Wire Transfer Approval Needed — CFO Office
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_849102_19041829.1727149800"

------=_Part_849102_19041829.1727149800
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: 7bit

<html>
<head><style>body{font-family:sans-serif;color:#1e293b;}</style></head>
<body>
<p>Team,</p>
<p>Please process the attached vendor invoice before EOD today. This payment is critical to our ongoing campus network expansion and is confidential due to contractual terms.</p>
<p>Kindly acknowledge receipt and confirm when the wire transmission has been submitted to the bank.</p>
<p>Access the wire disbursement schedule and beneficiary mandate here:<br>
<a href="https://secure-wire-transfer-portal.net/auth?id=INV-9921">https://secure-wire-transfer-portal.net/auth?id=INV-9921</a></p>
<p>Regards,<br>
<strong>Rajesh Iyer</strong><br>
Chief Financial Officer<br>
Annapoorna Educational Trust
</p>
</body>
</html>

------=_Part_849102_19041829.1727149800
Content-Type: application/pdf; name="Vendor_Invoice_INV-9921_WireInstructions.pdf"
Content-Disposition: attachment; filename="Vendor_Invoice_INV-9921_WireInstructions.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJeLjz9MKMSAwIG9iaiA8PC9UeXBlIC9DYXRhbG9nIC9QYWdlcyAyIDAgUj4+
ZW5kb2JqCjIgMCBvYmo8PC9UeXBlIC9QYWdlcyAvS2lkcyBbMyAwIFJdIC9Db3VudCAxPj4K
ZW5kb2JqCjMgMCBvYmo8PC9UeXBlIC9QYWdlIC9QYXJlbnQgMiAwIFIgL01lZGlhQm94IFsw
IDAgNjEyIDc5Ml0gL0NvbnRlbnRzIDQgMCBSPj4KZW5kb2JqCjQgMCBvYmo8PC9MZW5ndGgg
NTY+PnN0cmVhbQpCVAovRjEgMTIgVGYKNzIgNzIwIFRECihoZXhhZGVjaW1hbCBmYWtlIGF0
dGFjaG1lbnQgcGF5bG9hZCkgVGoKRVQKZW5kc3RyZWFtCmVuZG9iagp4cmVmCjAgNQowMDAw
MDAwMDAwIDY1NTM1IGYgCjAwMDAwMDAwMTUgMDAwMDAgbiAKMDAwMDAwMDA2MCAwMDAwMCBu
IAowMDAwMDAwMTE1IDAwMDAwIG4gCjAwMDAwMDAyMTYgMDAwMDAgbiAKdHJhaWxlcjw8L1Np
emUgNT4+CnN0YXJ0eHJlZgoyOTUKJSVFT0Y=

------=_Part_849102_19041829.1727149800--
`;

export const SAMPLE_CREDENTIAL_PHISH = `Received: by mail.annapoorna.edu.in (Postfix, from userid 1001)
	id 8F91B001CA; Thu, 24 Sep 2026 08:47:00 +0530 (IST)
Authentication-Results: mx.annapoorna.edu.in;
	dkim=none (no signature detected);
	spf=fail (mx.annapoorna.edu.in: domain of security-alert@paypa1-support.com does not designate 45.61.185.20 as permitted sender) smtp.mailfrom=security-alert@paypa1-support.com;
	dmarc=fail (p=reject dis=none) header.from=paypa1-support.com
Received: from exit-node-fr3.torproxy.net (exit-node-fr3.torproxy.net [45.61.185.20])
	by mail.annapoorna.edu.in (Postfix) with ESMTPS id 4K81920M
	for <accounts@annapoorna.edu.in>; Thu, 24 Sep 2026 08:46:25 +0530 (IST)
Received: from localhost (unknown [127.0.0.1])
	by exit-node-fr3.torproxy.net with SOCKS5;
	Thu, 24 Sep 2026 03:15:10 +0000
Message-ID: <alert-security-notice-2026-0924@paypa1-support.com>
Date: Thu, 24 Sep 2026 03:15:00 +0000
From: "PayPal Security" <security-alert@paypa1-support.com>
To: <accounts@annapoorna.edu.in>
Subject: Your account will be suspended — verify now
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: 7bit

<html>
<body>
<h3>Security Notification: Immediate Action Required</h3>
<p>We noticed unusual login attempts on your institutional billing profile. To prevent interruption of recurring services, verify your identity within 24 hours.</p>
<p><a href="https://paypa1-support.com/auth/login?verify=institution">Click here to verify institutional credentials</a></p>
<p>Reference: SEC-99120-TOR</p>
</body>
</html>
`;

export const SAMPLE_LEGITIMATE_NOTICE = `Received: by mail.annapoorna.edu.in (Postfix, from userid 1001)
	id 1B02919F00; Thu, 24 Sep 2026 07:30:00 +0530 (IST)
Authentication-Results: mx.annapoorna.edu.in;
	dkim=pass (good signature) header.d=annapoorna.edu.in;
	spf=pass (mx.annapoorna.edu.in: domain of registrar@annapoorna.edu.in designates 203.199.48.5 as permitted sender) smtp.mailfrom=registrar@annapoorna.edu.in;
	dmarc=pass (p=reject) header.from=annapoorna.edu.in
Received: from registrar-workstation-12.annapoorna.edu.in (registrar-workstation-12.annapoorna.edu.in [203.199.48.5])
	by mail.annapoorna.edu.in (Postfix) with ESMTPS id 90A8129B
	for <students-list@annapoorna.edu.in>; Thu, 24 Sep 2026 07:29:40 +0530 (IST)
Message-ID: <advisory-2026-ay-feestructure@annapoorna.edu.in>
Date: Thu, 24 Sep 2026 07:28:00 +0530
From: "Registrar Office" <registrar@annapoorna.edu.in>
To: <students-list@annapoorna.edu.in>
Subject: Re: Semester Fee Structure 2026-27
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Dear Students and Faculty,

Attached is the revised fee structure approved by the finance committee for Academic Year 2026-27.
The revised schedule applies to all undergraduate and postgraduate faculties.

Official circular is also posted on the intranet portal:
https://portal.annapoorna.edu.in/circulars/2026-fee-structure

Sincerely,
Office of the Registrar
Annapoorna Educational Trust
`;

export const DEMO_EMAIL_OPTIONS = [
  {
    id: 'sample-bec',
    name: 'URGENT: Wire Transfer Approval Needed (BEC Spoof)',
    sampleId: 'HDR_BEC_SPOOF_01',
    threat: 'Critical BEC Spoof',
    content: SAMPLE_BEC_WIRE_TRANSFER,
  },
  {
    id: 'sample-phish',
    name: 'Your account will be suspended (Tor Phish)',
    sampleId: 'HDR_PHISH_TOR_02',
    threat: 'High Phishing / Tor',
    content: SAMPLE_CREDENTIAL_PHISH,
  },
  {
    id: 'sample-legit',
    name: 'Semester Fee Structure 2026-27 (Legitimate)',
    sampleId: 'HDR_LEGIT_01',
    threat: 'Clean / Legitimate',
    content: SAMPLE_LEGITIMATE_NOTICE,
  },
];
