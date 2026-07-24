# Security Policy

## Scope

This app ships **without authentication** by design and is intended for a
local machine or trusted LAN (see README "Security notes"). Reports of the
absence of authentication are therefore out of scope; everything else —
XSS, SQL injection, XXE, decompression bombs, path traversal, IMAP client
issues — is very much in scope.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** on this repository
("Security" tab → "Report a vulnerability") rather than a public issue, so
users have a chance to update before details are public.

You can expect an acknowledgement within a week. There is no bug bounty —
this is a small open-source project — but reports are genuinely welcome and
will be credited in the fix commit unless you prefer otherwise.
