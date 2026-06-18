# Changelog

2026-06-18 v. 0.0.16

Změněno

* Roundcube nově odesílá lokálně přes 127.0.0.1:25 bez SMTP autentizace.
* SMTP autentizace je ponechána pro externí klienty a aplikace přes port 587 STARTTLS.
* Dovecot mail storage sjednocen na /var/vmail/<doména>/<uživatel>.
* INBOX již nemíří do /var/mail, ale do stejné Maildir struktury jako ostatní složky.
* LMTP username maska upravena tak, aby zachovala celou e-mailovou adresu včetně domény.

Přidáno

* Automatické zapnutí Postfix submission služby na portu 587.
* Nastavení SMTP AUTH přes Dovecot socket /var/spool/postfix/private/auth.
* Fallback TLS certifikát přes balík ssl-cert pro Postfix, pokud ještě neexistuje Let’s Encrypt certifikát.
* Automatické povolení základních mail portů ve UFW: 25/tcp, 587/tcp a 993/tcp.
* Roundcube výchozí složky Sent, Drafts, Trash a Junk.
* Automatické vytváření výchozích Roundcube složek pro nové schránky.
* URL escapování hesla v Roundcube DB DSN, aby nevadily speciální znaky v hesle.

Opraveno

* Opraven problém, kdy Roundcube padal při odesílání na chybu SMTP přihlášení.
* Opraven problém, kdy Dovecot LMTP odmítal existující schránky hláškou User doesn't exist.
* Opraveno usekávání domény z e-mailové adresy v LMTP autentizační masce.
* Opraveno rozdělení pošty mezi /var/mail a /var/vmail.
* Opraveno neukládání a nezobrazování odeslaných zpráv kvůli chybné konfiguraci výchozích složek.
* Opraveno chybné chování Roundcube při použití SMTP uživatele %u a hesla %p na lokálním portu 25.


## 2026-06-11 v. 0.0.15

### Změněno

* Sjednocen mail hostname napříč Postfixem, systémovým hostname, `/etc/mailname` a `/etc/hosts`.
* Postfix banner nastaven na čistý tvar `$myhostname ESMTP`.
* Mail stack upraven pro Dovecot 2.4 na Debianu 13.
* Vypnuta systémová PAM/passwd autentizace v Dovecotu, používá se SQL autentizace ORIS mail DB.
* Opraven Postfix chroot `/var/spool/postfix/etc/resolv.conf`.

### Přidáno

* Security Center sudoers oprávnění pro čtení stavů služeb, UFW, Fail2ban, logů a sken portů přes `ss`.
* UFW auto detekce naslouchajících portů.
* Podpora detekce pasivního FTP rozsahu z `/etc/vsftpd.conf`.
* Podpora UFW rozsahů portů typu `40000:40100`.

### Opraveno

* Opraveno chybné zobrazování sudo chyb v Security Center.
* Opraveno přidávání portů z UFW skenu do provisioneru.
* Opraveno parsování port range tokenů pro pasivní FTP.
