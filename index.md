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

## How is it usually installed

The only official installation method is by using cmdeploy.
It's a pyinfra script deploying all chatmail relay software with their config files on a specified server.
While it's probably good for newcomers and less experienced admins, it's extremely non-flexible:
cmdeploy requires a clean Debian&nbsp;12 system (good luck running on a different OS),
an SSH root access on port 22 (!!), overwrites all chatmail relay configs (so you have to edit them in your cloned repo, not on your server),
and it's impossible to change acmetool to a different ACME client without altering cmdeploy's source code and configs.

## And what have i just found

*This* is the documentation that will guide you through all the chatmail relay installation manually, by yourself.
No automation scripts. No magic commands. *You* understand how *your* server is configured.
