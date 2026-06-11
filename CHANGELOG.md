# Changelog

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
