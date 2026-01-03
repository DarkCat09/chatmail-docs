# chatmail on alpine

## General info about chatmail/relay

DeltaChat is a messenger that uses e-mail to transport OpenPGP-encrypted messages.
It works perfectly with any mail server (well, until the server ratelimits you),
but we wanted more features beyond the classical e-mail.

Chatmail relay is a mail server configuration consisting of:
* Postfix as an MTA
* Dovecot with a simple optimization patch as an IMAP server
* OpenDKIM to create and verify mail signatures
* nginx as a static file server and reverse proxy
* Iroh Relay as a p2p relay for in-chat apps (if a mail server doesn't host one, the default n0&nbsp;inc.'s relays are used)
* chatmail-turn for voice/video calls over WebRTC
* *chatmaild*, a set of scripts implementing DeltaChat-specific features:
  * rejecting non-encrypted mail (because relays are for DC only)
  * cleaning up old mail (messages are stored on clients, that's why our servers are called relays)
  * recording "last seen" timestamp
  * providing push notifications, iroh and turn URLs
  * registering a new account if provided username doesn't match an existing one
    (this is for simpler onboarding: when you scan a QR code, a client requests new random user+password and just logs&nbsp;in with them)
