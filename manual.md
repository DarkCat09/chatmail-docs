# chatmail on alpine

So, you want to help the DeltaChat network and host a public chatmail relay. Great!
Let's get started.

This documentation assumes that you're operating from an account called `user` (replace accordingly in `scp` commands),
which have sufficient permissions to run `doas` (if `sudo`, replace accordingly),
and your chatmail relay domain is `chat.example.com` (guess what? yes, replace it too).

## User for mailbox operations
```shell
doas addgroup -S -g 501 vmail
doas adduser -h /home/vmail -s /bin/false -G vmail -S -D -u 501 vmail
doas -u vmail mkdir -p /home/vmail/mail/chat.example.com  # replace with your domain
```

## User for iroh relay
```shell
doas addgroup -S iroh
doas adduser -s /bin/false -G iroh -S -D -H iroh
```

## chatmaild
Create a new virtualenv:
```shell
doas apk add python3 py3-virtualenv
doas python3 -m venv /opt/chatmaild
```

Let's use a separate directory for files we copy to the server during the installation:
```shell
mkdir ~/cm
cd ~/cm
```

On your PC, clone the official chatmail relay repo:
```shell
git clone https://github.com/chatmail/relay.git
```

Now, install chatmaild.

### Directly on a server
You can do everything on a server, but `crypt_r` dependency requires `gcc`,
and I'd suggest not to bring the whole C compiler.
If you're still not morally obligated to keep your relay as minimal as possible:
```shell
doas apk add git gcc musl-dev python3-dev
git clone https://github.com/chatmail/relay.git
cd relay
doas /opt/chatmaild/bin/pip install ./chatmaild
```

### From a musl local host
If your PC runs an x86_64 system with musl libc and the same Python version,
you can build Python packages (wheels) on it:
```shell
cd relay
pip wheel -w ./dist ./chatmaild
```
Then, upload them to your server:
```shell
scp -P 8022 ./dist/*.whl user@chat.example.com:/home/user/cm
cd ..
```
And, on the server:
```shell
doas /opt/chatmaild/bin/pip install ./*.whl
rm ./*.whl
```

### From a local host with containerd
Alternatively, if your main system is not musl, or its CPU arch doesn't match with server's one,
build Python packages in a container, emulator, etc.

For example, with Docker:
```shell
cd relay
docker run -it --rm -v ./:/src alpine:latest sh -c 'apk add python3 py3-pip gcc musl-dev python3-dev && pip wheel -w /src/dist /src/chatmaild'
```
Upload:
```shell
scp -P 8022 ./dist/*.whl user@chat.example.com:/home/user/cm
sudo rm -rf dist chatmaild/src/chatmaild.egg-info  # to prevent permission issues since docker is run as root
cd ..
```
Install:
```shell
doas /opt/chatmaild/bin/pip install ./*.whl
rm ./*.whl
```

## cron and init.d
On your PC, clone the repo and upload all files from it:
```shell
git clone https://git.dc09.xyz/chatmail/openrc.git
cd openrc
scp -P 8022 ./* user@chat.example.com:/home/user/cm
cd ..
```
Add new crontab jobs:
```shell
doas crontab -l >cron.bkp  # saving previous crontab to combine with new one
cat cron.bkp crontab | doas crontab -
rm cron.bkp crontab
```
Place chatmail OpenRC scripts:
```shell
doas chown root: ./*
doas chmod 755 ./*
doas mv ./* /etc/init.d
```

## TURN server for calls
On your server, download the official binary, verify its integrity, place to `/usr/local/bin`
and enable its OpenRC service (which was installed in the previous step):
```shell
curl -L -o ./chatmail-turn 'https://github.com/chatmail/chatmail-turn/releases/download/v0.3/chatmail-turn-x86_64-linux'
echo '841e527c15fdc2940b0469e206188ea8f0af48533be12ecb8098520f813d41e4 chatmail-turn' | sha256sum -c
doas chown root: chatmail-turn
doas chmod 755 chatmail-turn
doas mv chatmail-turn /usr/local/bin/
doas rc-update add chatmail-turn
```

## Iroh Relay
Same goes for iroh: download an official binary (v0.35.0 is chosen on purpose,
newer releases until v1 are considered non-stable and contain breaking changes),
verify its integrity, place the binary in the system, enable its init.d service:
```shell
curl -L -o iroh.tar.gz 'https://github.com/n0-computer/iroh/releases/download/v0.35.0/iroh-relay-v0.35.0-x86_64-unknown-linux-musl.tar.gz'
tar xzf iroh.tar.gz
rm iroh.tar.gz
echo '45c81199dbd70f8c4c30fef7f3b9727ca6e3cea8f2831333eeaf8aa71bf0fac1 iroh-relay' | sha256sum -c
doas chown root: iroh-relay
doas chmod 755 iroh-relay
doas mv iroh-relay /usr/local/bin/
doas rc-update add iroh-relay
```

## chatmaild and iroh configs
On your PC, install cmdeploy into a virtualenv, generate a chatmaild config and adjust it, then upload it
(with an iroh config, since we already installed it so why not configure it now)
```shell
cd relay
python -m venv venv
venv/bin/pip install -e ./chatmaild -e ./cmdeploy
venv/bin/cmdeploy init chat.example.com
vim chatmail.ini  # use any preferred editor
# not all parameters make sense since we're doing a manual install
scp -P 8022 \
  ./chatmail.ini \
  ./cmdeploy/src/cmdeploy/iroh-relay.toml \
  user@chat.example.com:/home/user/cm
cd ..
```
Let's get back to the server:
```shell
# mailname config (replace the domain!)
echo 'chat.example.com' | doas tee /etc/mailname
# chatmaild and iroh
doas chown root: chatmail.ini iroh-relay.toml
doas mv chatmail.ini iroh-relay.toml /etc/
```

## Custom APK repo
Not everything in Alpine is packaged with required feature flags or patches.
I maintain a separate APK repository on my Forgejo which includes [Dovecot](https://git.dc09.xyz/chatmail/dovecot),
[OpenDKIM](https://git.dc09.xyz/chatmail/opendkim) and a rewrite of [newemail](https://git.dc09.xyz/chatmail/newemail).
Packages are built with CI, you can check the workflow configurations.

To add the repo to the server:
```shell
cd /etc/apk/keys
doas curl -JO https://git.dc09.xyz/api/packages/chatmail/alpine/key
echo '@chatmail https://git.dc09.xyz/api/packages/chatmail/alpine/3.23/chatmail' | doas tee -a /etc/apk/repositories
cd ~/cm
```

Alternatively, you can build those packages by yourself, see [Alpine Wiki](https://wiki.alpinelinux.org/wiki/Abuild_and_Helpers).
You'll need to do `abuild-keygen -a`, copy that repo key to server's `/etc/apk/keys`,
clone git repos with APKBUILDs (listed above) and run `abuild -r` there, then upload and install `.apk`-s from `~/packages/chatmail/x86_64/`.

## OpenDKIM
```shell
doas apk add opendkim@chatmail opendkim-libs@chatmail opendkim-utils@chatmail
doas apk add dnssec-root
doas apk add postfix
```

`doas vim /etc/opendkim/opendkim.conf` \
Put this config replacing a domain (in one line marked with `<--`)
```
Syslog yes
SyslogSuccess yes
LogWhy no

Canonicalization relaxed/simple
OversignHeaders from,reply-to,subject,date,to,cc,resent-date,resent-from,resent-sender,resent-to,resent-cc,in-reply-to,references,list-id,list-help,list-unsubscribe,list-subscribe,list-post,list-owner,list-archive,autocrypt
SignHeaders *,+autocrypt,+content-type

On-BadSignature reject
On-KeyNotFound reject
On-NoSignature reject
DNSTimeout 60

Domain chat.example.com  # <-- CHANGE TO YOUR DOMAIN
Selector opendkim
KeyFile /etc/dkimkeys/opendkim.private
KeyTable /etc/dkimkeys/KeyTable
SigningTable refile:/etc/dkimkeys/SigningTable

ScreenPolicyScript /etc/opendkim/screen.lua
FinalPolicyScript /etc/opendkim/final.lua

UserID opendkim
UMask 007
Socket local:/var/spool/postfix/opendkim/opendkim.sock
PidFile /run/opendkim/opendkim.pid

TrustAnchorFile /usr/share/dnssec-root/trusted-key.key

MTA ORIGINATING
InternalHosts -
```

Now, upload Lua scripts, from a cloned repo on your PC:
```shell
cd relay
scp -P 8022 ./cmdeploy/src/cmdeploy/opendkim/*.lua user@chat.example.com:/home/user/cm
cd ..
```
On the server:
```shell
doas chown root: *.lua
doas mv screen.lua final.lua /etc/opendkim/
```
```shell
doas mkdir /etc/dkimkeys
```

`doas vim /etc/dkimkeys/KeyTable` \
Put this line adjusting a domain 2 times:
```
opendkim._domainkey.chat.example.com chat.example.com:opendkim:/etc/dkimkeys/opendkim.private
```

`doas vim /etc/dkimkeys/SigningTable` \
Put this line adjusting a domain, again 2 times:
```
*@chat.example.com opendkim._domainkey.chat.example.com
```

Change OpenDKIM configs owner/permissions:
```shell
doas chown opendkim: /etc/opendkim
doas chown -R opendkim: /etc/dkimkeys
doas chmod 750 /etc/opendkim /etc/dkimkeys
```

Generate a new DKIM key for your mail server (replace domain)
```shell
doas -u opendkim opendkim-genkey -D /etc/dkimkeys -d chat.example.com -s opendkim
```

And create a directory for OpenDKIM's unix socket, with which Postfix will be communicating:
```shell
doas mkdir /var/spool/postfix/opendkim
doas chown opendkim: /var/spool/postfix/opendkim
doas chmod 750 /var/spool/postfix/opendkim
```

Enable the init.d service:
```shell
doas rc-update add opendkim
```

## Dovecot
The custom APK repo contains Dovecot 2.3.21.1 (in 2.4 they completely broke the config format compatibility)
built with a [simple patch for better performance](https://github.com/chatmail/dovecot/blob/master/debian/patches/remove-500ms-idle-debounce.patch)
```shell
doas apk add dovecot@chatmail dovecot-openrc@chatmail dovecot-lmtpd@chatmail dovecot-lua@chatmail
```

`doas vim /etc/dovecot/dovecot.conf` \
Put the contents replacing a domain (in 2 lines), adjusting TLS certs location and mailbox quotas
```
protocols = imap lmtp
auth_mechanisms = plain

default_client_limit = 20000

# Each connection is handled by a separate `imap` process
service imap {
  process_limit = 50000
}

mail_server_admin = mailto:root@chat.example.com  # <-- HERE
mail_server_comment = Chatmail server

# Mailbox compression and limits
mail_plugins = zlib quota
# Chatmail custom capabilities
imap_capability = +XDELTAPUSH XCHATMAIL

# Authentication
passdb {
  driver = dict
  args = /etc/dovecot/auth.conf
}
userdb {
  driver = dict
  args = /etc/dovecot/auth.conf
}

##
## Mailbox locations and namespaces

# /home/vmail/mail/(host)/(user)
mail_location = maildir:/home/vmail/mail/chat.example.com/%u  # <-- HERE

# change locking behavior according to
# alpine's default dovecot config
mbox_write_locks = fcntl

# index & cache files are not very useful for chatmail
mail_cache_max_size = 500K

namespace inbox {
  inbox = yes

  mailbox Drafts {
    special_use = \Drafts
  }
  mailbox Junk {
    special_use = \Junk
  }
  mailbox Trash {
    special_use = \Trash
  }

  mailbox Sent {
    special_use = \Sent
  }
  mailbox "Sent Messages" {
    special_use = \Sent
  }
}

mail_uid = vmail
mail_gid = vmail
mail_privileged_group = vmail

##
## Mail processes

# Pass all IMAP METADATA requests to the chatmail-metadata service
mail_attribute_dict = proxy:/run/chatmail-metadata/metadata.socket:metadata

protocol imap {
  mail_plugins = $mail_plugins imap_quota last_login
  # in case you want to enable IMAP COMPRESS (see `imap_compress` in chatmail.ini)
  #mail_plugins = $mail_plugins imap_quota last_login imap_zlib

  imap_metadata = yes
}

plugin {
  last_login_dict = proxy:/run/chatmail-lastlogin/lastlogin.socket:lastlogin
  #last_login_key = last-login/%u  # default
  last_login_precision = s
}

protocol lmtp {
  mail_plugins = $mail_plugins mail_lua notify push_notification push_notification_lua
}

plugin {
  zlib_save = gz
}

plugin {
  imap_compress_deflate_level = 6
}

plugin {
  # ADJUST MAILBOX QUOTAS
  quota = maildir:User quota
  quota_rule = *:storage=100M   # <-- max_mailbox_size in chatmail.ini
  quota_max_mail_size=31457280  # <-- max_message_size
  quota_grace = 0
}

# push_notification configuration
plugin {
  push_notification_driver = lua:file=/etc/dovecot/push_notification.lua
}

service lmtp {
  user = vmail

  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}

service auth-worker {
  # Drop privileges we don't need
  user = vmail
}

service imap-login {
  # High-performance mode
  service_count = 0

  # Increase virtual memory size limit
  vsz_limit = 1G

  # Avoid startup latency for new connections.
  # Should be set to at least the number of CPU cores
  # according to the documentation
  process_min_avail = 10
}

service anvil {
  # No point in anvil penalty as it detects brute-forcing
  # only by IP address, not by username.
  # A correct IP address is not passed to Dovecot anyway
  unix_listener anvil-auth-penalty {
    mode = 0
  }
}

# ADJUST PATHS TO TLS CERTS
ssl = required
ssl_cert = </etc/letsencrypt/live/chat.example.com/fullchain.pem  # <-- HERE
ssl_key = </etc/letsencrypt/live/chat.example.com/privkey.pem     # <-- HERE
ssl_dh = </etc/dovecot/dh.pem
ssl_min_protocol = TLSv1.3
ssl_prefer_server_ciphers = yes

# Hibernate IDLE users to save memory and CPU resources
# NOTE: this will have no effect if imap_zlib plugin is used
#       i.e. when IMAP COMPRESS is enabled
imap_hibernate_timeout = 30s
service imap {
  # Note that this change will allow any process running as
  # $default_internal_user (dovecot) to access mails as any other user.
  # This may be insecure in some installations, which is why this isn't
  # done by default.
  unix_listener imap-master {
    user = $default_internal_user
  }
}
service imap {
  extra_groups = $default_internal_group
}
service imap-hibernate {
  unix_listener imap-hibernate {
    mode = 0660
    group = $default_internal_group
  }
}
```

`doas vim /etc/dovecot/dh.pem` \
Copy the contents below, or [from Debian package](https://salsa.debian.org/debian/dovecot/-/blob/ffffbace9e/debian/dh.pem),
or alternatively, generate dhparams on your PC with `openssl dhparam 4096 >dh.pem` (takes some time)
```
-----BEGIN DH PARAMETERS-----
MIICDAKCAgEAyvlzzX8sCG2iHMMa0ywepwE6ssGio+TJHhppS0dUYVIgUulUIa8I
h1EGOH48hMhM0fHXR/xbBrIAygQGJwGwhVZbE+iXKjGF/i+0ms4eCSrhw//HQcVH
jq5UD7aDKTfAwdIqp+a5GkId/UZUVr9dVG8OfR81EGkBgQEp2P3A9nxux8KfNquj
t1cZhwwkeAVS0/FG4pk/vFK+z1qsGAxluE8hdEmbgL/EqzgRvWLZNDTr2BE0OS7L
rCYZDwwvcJVuidVHW9GrlgwO7PC2Y4sFYfQHuhpMaoLLl3C4OiYb7UGE0cNm7W7D
zy5ckuhNimWmRw3HlxiB4pNfLpPWtA2b+oyXlmKZDUgW3tUsdOzIbfMwDctmGF1G
iivBJk72ltjMO7+ewbJ0EqtqyUiHi+zBbIOalQnwdDE8zE6ka/z5T6QLY2jjriz6
DwtqLRRcSJrId3qY1ZbJRqxpq4rUmWJFHC4j8+t6Wh0qwYpO084p8n9Y2/ddqmCD
Po+aiDwvA8BlNDSpGp7gGztghuo9oljiUPHlM/evV4wI8/sPUNrZIc5d1gHJZDtB
PN9RcPA8+JhYzlxuifjVyLiyopR6kxjrn5HOMuQ3ZUaZjoHRPrRNNTv5Drr0zKr0
eEzshgR6e3LDFUB1QRC1Xg1ZGq2SwL2l+lqsJMSMnKH8jO8WBTjujS8CAQICAgFF
-----END DH PARAMETERS-----
```

Upload Lua scripts from the cloned chatmail/relay repo:
```shell
cd relay
scp -P 8022 \
  ./cmdeploy/src/cmdeploy/dovecot/auth.conf \
  ./cmdeploy/src/cmdeploy/dovecot/push_notification.lua \
  user@chat.example.com:/home/user/cm
cd ..
```
On the server:
```shell
doas chown root: auth.conf push_notification.lua
doas mv auth.conf push_notification.lua /etc/dovecot
```

Since we may need to handle many connections, let's adjust the limits:

```shell
doas sysctl -w fs.inotify.max_user_instances=65535
doas sysctl -w fs.inotify.max_user_watches=65535
```

`doas vim /etc/sysctl.d/inotify.conf`
```ini
fs.inotify.max_user_instances = 65535
fs.inotify.max_user_watches = 65535
```

`doas vim /etc/conf.d/dovecot`
```shell
rc_ulimit="-n 20000"
```

Enable OpenRC services for Dovecot and related chatmaild scripts:
```shell
for svc in dovecot doveauth chatmail-metadata lastlogin; do doas rc-update add "$svc"; done
```

## Postfix
`doas vim /etc/postfix/main.cf` \
Put the config replacing a domain (3 times), adjusting TLS certs location and message size quota
```
compatibility_level = 3.6

myorigin = chat.example.com  # <-- HERE
smtpd_banner = $myhostname ESMTP $mail_name
biff = no
readme_directory = no

append_dot_mydomain = no

# Uncomment the next line to generate "delayed mail" warnings
#delay_warning_time = 4h

# TLS parameters
smtpd_tls_cert_file=/etc/letsencrypt/live/chat.example.com/fullchain.pem  # <-- HERE
smtpd_tls_key_file=/etc/letsencrypt/live/chat.example.com/privkey.pem     # <-- HERE
smtpd_tls_security_level=may

smtp_tls_CAfile=/etc/ssl/certs/ca-certificates.crt
smtp_tls_security_level=verify
# Send SNI when connecting to other servers
smtp_tls_servername = hostname
smtp_tls_session_cache_database = lmdb:${data_directory}/smtp_scache
smtp_tls_policy_maps = inline:{nauta.cu=may}
smtp_tls_protocols = >=TLSv1.2
smtp_tls_mandatory_protocols = >=TLSv1.2
# Disable anonymous cipher suites and known insecure algorithms
smtpd_tls_exclude_ciphers = aNULL, RC4, MD5, DES
# Override client's preference order
tls_preempt_cipherlist = yes

smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination

myhostname = chat.example.com  # <-- HERE
alias_maps = lmdb:/etc/postfix/aliases
alias_database = lmdb:/etc/postfix/aliases

mydestination =
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
message_size_limit = 31457280  # <-- max_message_size in chatmail.ini
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all

virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_mailbox_domains = chat.example.com  # <-- HERE

mua_client_restrictions = permit_sasl_authenticated, reject
mua_sender_restrictions = reject_sender_login_mismatch, permit_sasl_authenticated, reject
mua_helo_restrictions = permit_mynetworks, reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname, permit

# 1:1 map MAIL FROM to SASL login name
smtpd_sender_login_maps = regexp:/etc/postfix/login_map

# Do not lookup SMTP client hostnames to reduce delays
# and avoid unnecessary DNS requests
smtpd_peername_lookup = no
```

`doas vim /etc/postfix/master.cf` \
Just copy the config (unless you had to change filtermail ports in chatmail.ini for some weird reason &mbsp; in that case change them respectively in 5 lines)
```
# ==========================================================================
# service type  private unpriv  chroot  wakeup  maxproc command + args
#               (yes)   (yes)   (no)    (never) (100)
# ==========================================================================
smtp      inet  n       -       y       -       -       smtpd 
  -o smtpd_tls_security_level=encrypt
  -o smtpd_tls_mandatory_protocols=>=TLSv1.2
  -o smtpd_proxy_filter=127.0.0.1:10081
submission inet n       -       y       -       5000    smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_tls_mandatory_protocols=>=TLSv1.3
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_client_restrictions=$mua_client_restrictions
  -o smtpd_helo_restrictions=$mua_helo_restrictions
  -o smtpd_sender_restrictions=$mua_sender_restrictions
  -o smtpd_recipient_restrictions=
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o smtpd_client_connection_count_limit=1000
  -o smtpd_proxy_filter=127.0.0.1:10080
smtps     inet  n       -       y       -       5000    smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_tls_security_level=encrypt
  -o smtpd_tls_mandatory_protocols=>=TLSv1.3
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_client_restrictions=$mua_client_restrictions
  -o smtpd_helo_restrictions=$mua_helo_restrictions
  -o smtpd_sender_restrictions=$mua_sender_restrictions
  -o smtpd_recipient_restrictions=
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o smtpd_client_connection_count_limit=1000
  -o smtpd_proxy_filter=127.0.0.1:10080

#628       inet  n       -       y       -       -       qmqpd
pickup    unix  n       -       y       60      1       pickup
cleanup   unix  n       -       y       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
#qmgr     unix  n       -       n       300     1       oqmgr
tlsmgr    unix  -       -       y       1000?   1       tlsmgr
rewrite   unix  -       -       y       -       -       trivial-rewrite
bounce    unix  -       -       y       -       0       bounce
defer     unix  -       -       y       -       0       bounce
trace     unix  -       -       y       -       0       bounce
verify    unix  -       -       y       -       1       verify
flush     unix  n       -       y       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       y       -       -       smtp
relay     unix  -       -       y       -       -       smtp
        -o syslog_name=postfix/$service_name
#       -o smtp_helo_timeout=5 -o smtp_connect_timeout=5
showq     unix  n       -       y       -       -       showq
error     unix  -       -       y       -       -       error
retry     unix  -       -       y       -       -       error
discard   unix  -       -       y       -       -       discard
lmtp      unix  -       -       y       -       -       lmtp
anvil     unix  -       -       y       -       1       anvil
scache    unix  -       -       y       -       1       scache
postlog   unix-dgram n  -       n       -       1       postlogd
filter    unix -        n       n       -       -       lmtp

# Local SMTP server for reinjecting outgoing filtered mail
127.0.0.1:10025 inet  n       -       n       -       100      smtpd
  -o syslog_name=postfix/reinject
  -o milter_macro_daemon_name=ORIGINATING
  -o smtpd_milters=unix:opendkim/opendkim.sock
  -o cleanup_service_name=authclean

# Local SMTP server for reinjecting incoming filtered mail
127.0.0.1:10026 inet  n       -       n       -       100      smtpd
  -o syslog_name=postfix/reinject_incoming
  -o smtpd_milters=unix:opendkim/opendkim.sock

# Cleanup `Received` headers for authenticated mail
# to avoid leaking client IP
#
# We do not do this for received mails
# as this will break DKIM signatures
# if `Received` header is signed
#
# This service also rewrites
# Subject with `[...]`
# to make sure the users
# cannot send unprotected Subject
authclean unix  n       -       -       -       0       cleanup
  -o header_checks=regexp:/etc/postfix/submission_header_cleanup
```

Upload some more configs:
```shell
cd relay
scp -P 8022 \
  ./cmdeploy/src/cmdeploy/postfix/submission_header_cleanup \
  ./cmdeploy/src/cmdeploy/postfix/login_map \
  user@chat.example.com:/home/user/cm
cd ..
```
```shell
doas chown root: submission_header_cleanup login_map
doas mv submission_header_cleanup login_map /etc/postfix/
```
Generate an alias database:
```shell
doas newaliases
```
Add to OpenDKIM group so Postfix can access the socket:
```shell
doas addgroup postfix opendkim
```
Fix resolv.conf in chroot:
```shell
doas mkdir -p /var/spool/postfix/etc
doas cp /etc/resolv.conf /var/spool/postfix/etc
```

Enable OpenRC services &mdash; Postfix and chatmaild filtermail scripts:
```shell
for svc in postfix filtermail filtermail-incoming; do doas rc-update add "$svc"; done
```

## nginx
Install nginx web server and `stream` module
```shell
doas apk add nginx nginx-mod-stream
```

`doas vim /etc/nginx/nginx.conf` \
Put the contents replacing a domain (in 5 lines) and adjusting TLS certs location,
leaving TLS disabled for now until we setup certbot
```
load_module modules/ngx_stream_module.so;

user nginx;
worker_processes auto;
pcre_jit on;

error_log /var/log/nginx/error.log warn;

worker_rlimit_nofile 2048;
events {
  worker_connections 2048;
}

stream {
  map $ssl_preread_alpn_protocols $proxy {
    default 127.0.0.1:8443;
    ~\bsmtp\b 127.0.0.1:465;
    ~\bimap\b 127.0.0.1:993;
  }

  server {
    listen 443;
    listen [::]:443;
    ssl_preread on;
    proxy_pass $proxy;
  }
}

http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;

  server_tokens off;

  sendfile on;
  tcp_nopush on;

  gzip on;

  ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
  ssl_prefer_server_ciphers on;
  # UNCOMMENT AFTER SETTING UP CERTBOT
  #ssl_certificate /etc/letsencrypt/live/chat.example.com/fullchain.pem;    # <-- HERE
  #ssl_certificate_key /etc/letsencrypt/live/chat.example.com/privkey.pem;  # <-- HERE

  server {
    listen 80;
    listen [::]:80;
    server_name chat.example.com www.chat.example.com mta-sts.chat.example.com;  # <-- HERE
    location / {
      return 301 https://$host$request_uri;
    }
  }

  server {
    # REPLACE AFTER SETTING UP CERTBOT
    #listen 127.0.0.1:8443 ssl default_server;
    listen 127.0.0.1:8443 default_server;

    server_name chat.example.com mta-sts.chat.example.com;  # <-- HERE
    root /var/www/html;
    index index.html;

    location / {
      try_files $uri $uri/ =404;
    }

    location /new {
      if ($request_method = GET) {
        return 301 dcaccount:https://chat.example.com/new;  # <-- HERE
      }
      proxy_pass http://unix:/run/newemail/actix.sock;
      proxy_http_version 1.1;
    }

    location /relay {
      proxy_pass http://127.0.0.1:3340;
      proxy_http_version 1.1;
      proxy_set_header Connection "upgrade";
      proxy_set_header Upgrade $http_upgrade;
    }

    location /relay/probe {
      proxy_pass http://127.0.0.1:3340;
      proxy_http_version 1.1;
    }

    location /generate_204 {
      proxy_pass http://127.0.0.1:3340;
      proxy_http_version 1.1;
    }
  }

  server {
    # REPLACE AFTER SETTING UP CERTBOT
    #listen 127.0.0.1:8443 ssl;
    listen 127.0.0.1:8443;

    server_name www.chat.example.com;  # <-- HERE
    return 301 https://chat.example.com$request_uri;  # <-- HERE
  }
}
```

Enable init.d, validate the config (just in case) and start nginx:
```shell
doas rc-update add nginx
doas service nginx checkconfig
doas service nginx start
```

## certbot
Install to a virtualenv:
```shell
doas python3 -m venv /opt/certbot
doas /opt/certbot/bin/pip install certbot certbot-nginx
```
Request certificates via http-01 challenge:
```shell
doas /opt/certbot/bin/certbot certonly --nginx
```

`doas vim /etc/nginx/nginx.conf` \
* ensure that TLS certs location is correct
* uncomment them (find 1 comment: `# UNCOMMENT AFTER SETTING UP CERTBOT`)
* enable serving over TLS by adding `ssl` option to `listen` on 8443 (find 2 comments: `# REPLACE AFTER SETTING UP CERTBOT`)

Let's validate the modified config and restart nginx:
```shell
doas service nginx checkconfig
doas service nginx restart
```

Also, don't forget that TLS certs should be automatically renewed.
Let's ask certbot to check them, and renew if needed, every day at 01:02
```shell
doas crontab -l >cron.bkp
echo '2 1  * * * /opt/certbot/bin/certbot renew &>/var/log/renew.log' >cron.add
cat cron.bkp cron.add | doas crontab -
rm cron.bkp cron.add
```

When certs are updated, programs which use TLS should re-read them, so we setup a deploy hook:
`doas vim /etc/letsencrypt/renewal-hooks/deploy/reload.sh`
```shell
#!/bin/sh -eu
for svc in nginx postfix dovecot; do
  /sbin/rc-service "$svc" reload
done
```
And allow execution of this script:
```shell
doas chmod 750 /etc/letsencrypt/renewal-hooks/deploy/reload.sh
```

# newemail
This is a chatmaild service which just generates random username and password
when a client requests them as a part of signing up process.
```shell
doas apk add newemail@chatmail
doas rc-update add newemail
```

## Webpages
As a chatmail relay admin, you probably want to tell a bit about your instance
and show a QR code and a link for users to conveniently proceed to registration.
Static pages should be put into `/var/www/html` directory.

### Official pages
To build and host a static website from cmdeploy, run these commands on your PC: \
(yes, cmdeploy doesn't have a CLI interface to just build pages, so here's a one-line command)
```shell
cd relay
venv/bin/python -c 'from chatmaild import config; from cmdeploy import www; from pathlib import Path; www.build_webpages(Path("www/src"), Path("www/build"), config.read_config("chatmail.ini"))'
cd www/build
tar cf site.tar ./*
scp -P 8022 ./site.tar user@chat.example.com:/home/user/cm
cd ../../..
```
And then, on the server:
```shell
doas mkdir -p /var/www/html
doas tar xf site.tar -C /var/www/html --no-same-owner --no-same-permissions
rm site.tar
```

### Custom pages
Write whatever you want and place in `/var/www/html/`.
A link for account sign up is `dcaccount:https://chat.example.com/new`,
a QR code just contains the same link (please use a local QR code generator and/or validate the contents).

In case you're building some custom registration system (why??),
you may want to generate links/QRs like `dclogin:username@chat.example.com/?p=password&v=1`

## .well-known routes
```shell
doas mkdir -p /var/www/html/.well-known
doas vim /var/www/html/.well-known/mta-sts.txt
```
Put the contents replacing a domain:
```
version: STSv1
mode: enforce
mx: chat.example.com
max_age: 2419200
```

```shell
doas mkdir -p /var/www/html/.well-known/autoconfig/mail
doas vim /var/www/html/.well-known/autoconfig/mail/config-v1.1.xml
```
Put the contents, use find+replace `chat.example.com` in your editor
```
<?xml version="1.0" encoding="UTF-8"?>

<clientConfig version="1.1">
  <emailProvider id="chat.example.com">
    <domain>chat.example.com</domain>
    <displayName>chat.example.com chatmail</displayName>
    <displayShortName>chat.example.com</displayShortName>
    <incomingServer type="imap">
      <hostname>chat.example.com</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <incomingServer type="imap">
      <hostname>chat.example.com</hostname>
      <port>143</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <incomingServer type="imap">
      <hostname>chat.example.com</hostname>
      <port>443</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>chat.example.com</hostname>
      <port>465</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
    <outgoingServer type="smtp">
      <hostname>chat.example.com</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
    <outgoingServer type="smtp">
      <hostname>chat.example.com</hostname>
      <port>443</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>
```

## cmdeploy git commit
It is not used at all, probably was made for tests as a marker for a successful deployment.
But you may include it if you want, it may help to determine what commit your installation is based on.
```shell
echo 'bcf2fdb5d0205851c94382f3d8474dc637755211' | doas tee /etc/chatmail-version
doas chmod 600 /etc/chatmail-version
```

## Finally. Start all the services
```shell
doas openrc
```
You may need to restart OpenDKIM, otherwise it fails to sign messages,
and honestly, I don't know why.

## DNS records
There's another step left. I promise it's the last one.

Point domains to your server IP address, this is what you already have done long ago:
```
chat.example.com.           A      1.2.3.4
www.chat.example.com.       CNAME  chat.example.com.
mta-sts.chat.example.com.   CNAME  chat.example.com.
```

MX record specifying which mail server handles e-mail for this domain: \
10 is a priority value
```
chat.example.com.           MX     10  chat.example.com.
```

Enable MTA-STS: \
id can be `$(date +%Y%m%d%H%M)` as chatmail does,
but `id=1` should be okay too
```
_mta-sts.chat.example.com.  TXT    "v=STSv1; id=202512311957"
```

DKIM signing key: \
open `/etc/dkimkeys/opendkim.txt` and copy the p= value
(it may be split into multiple quoted strings, copy all of that)
```
opendkim._domainkey.chat.example.com.  TXT  "v=DKIM1;k=rsa;p=ABcd123...;s=email;t=s"
```

Instruct mail servers to reject messages without a signature:
```
_adsp._domainkey.chat.example.com.     TXT  "dkim=discardable"
```

SPF record means that e-mail from this domain must be received only from
an address specified in the A record, DMARC tells to reject mail on
SPF or DKIM verification failure
```
chat.example.com.           TXT    "v=spf1 a ~all"
_dmarc.chat.example.com.    TXT    "v=DMARC1;p=reject;adkim=s;aspf=s"
```

SRV records help clients to determine host and port of mail services
```
_submission._tcp.chat.example.com.   SRV  0  1  587  chat.example.com.
_submissions._tcp.chat.example.com.  SRV  0  1  465  chat.example.com.
_imap._tcp.chat.example.com.         SRV  0  1  143  chat.example.com.
_imaps._tcp.chat.example.com.        SRV  0  1  993  chat.example.com.
```
