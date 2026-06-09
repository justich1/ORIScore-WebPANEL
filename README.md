# ORIScore WebPANEL

ORIScore WebPANEL je administrační webový panel pro správu vlastního Linux webserveru. Projekt kombinuje lehké PHP rozhraní s Python provisionerem, který přes frontu úloh provádí systémové změny bezpečněji mimo samotný webový proces.

Panel je určený pro správu webů, reverzních proxy, databází, FTP účtů, HTTPS certifikátů, e-mailového serveru, firewallu, WireGuardu, systémových služeb, logů, záloh a základního monitoringu serveru.

> **Stav projektu:** vývojová/beta verze.

## Hlavní funkce

### Webhosting

- správa webů přes Nginx vhosty,
- zakládání a mazání webů,
- správa root adresáře webu,
- podpora PHP-FPM,
- vlastní PHP nastavení pro weby,
- volitelné pretty URLs,
- vlastní Nginx direktivy,
- přesměrování na HTTPS,
- HSTS,
- phpMyAdmin dostupný přes Nginx snippet.

### Reverzní proxy

- vytváření proxy domén,
- přeposílání na HTTP/HTTPS upstream,
- volitelné HTTPS,
- HSTS,

### Databáze

- MariaDB backend,
- interní databáze `oris_panel`,
- samostatná mail databáze `oris_mail`,
- možnost vytvoření databáze k webu,
- reset DB hesla,
- smazání DB k webu,
- přístup k phpMyAdmin.

### FTP

- správa FTP účtů přes vsftpd,
- vytvoření účtu k webu,
- reset hesla,
- odstranění účtu,
- oprava práv webového adresáře,
- pasivní FTP rozsah v konfiguraci vsftpd.

### Certifikáty a ACME

- Certbot/Let’s Encrypt joby,
- test ACME challenge,
- vystavení certifikátu pro web,
- vystavení certifikátu pro proxy,
- obnova certifikátů,
- nastavitelný ACME webroot.

### E-mail server

Panel obsahuje moduly pro správu mail serveru nad Postfixem, Dovecotem, Rspamd, Redisem a Roundcube.

Podporované části:

- mail domény,
- mailboxy,
- aliasy,
- DKIM klíče,
- DNS TXT výpis pro DKIM,
- Roundcube konfigurace,
- Rspamd nastavení,
- Bayes backup/restore,
- full backup/restore mail konfigurace,
- test mail stacku.

### Bezpečnost

- UFW ovládání,
- povolení/odebrání pravidel firewallu,
- Fail2ban správa,
- ban/unban IP adres,
- permanentní blokace IP,
- recidive jail,
- ochrana phpMyAdmin,
- jednoduché Nginx rate limit snippety,
- security log `/var/log/oris-security.log`.

### WireGuard

- serverové nastavení WireGuardu,
- správa peerů,
- generování klientské konfigurace,
- QR kódy pro klienty,
- enable/disable peeru,
- regenerace peeru,
- restart WireGuard služby.

### Cron

- správa cron úloh k webům,
- zápis do `/etc/cron.d/oris-sites`,
- ruční spuštění cron jobu přes provisioner,
- evidence posledního běhu, návratového kódu a výstupu.

### Systém a monitoring

- fronta úloh `jobs`,
- přehled běžících/dokončených/chybových úloh,
- logy,
- ovládání systemd služeb,
- síťový provoz,
- CPU/RAM/disk monitoring přes `oris-stats-worker`,
- konfigurace serverových souborů,
- konfigurace PHP a vhostu samotného administračního panelu.

### API

- API tokeny,
- scopes,
- expirace tokenů,
- API Explorer s ukázkou požadavků a cURL příkazů.

## Překlady

Projekt obsahuje vícejazyčné UI slovníky v adresáři:

```text
ui/language/
```

Aktuálně jsou připravené jazyky:

```text
cs.php  - čeština
en.php  - angličtina
de.php  - němčina
```

Jazyky se načítají podle obsahu v `language/`:

Přepínač jazyků je součástí horní lišty panelu.

> **Poznámka:** překladový editor v panelu není aktuálně funkční. Překlady je teď vhodné upravovat přímo v souborech `ui/language/*.php`.

## Struktura projektu

```text
oris_webserver/
├── backend/
│   ├── requirements.txt
│   └── oris_provisioner/
│       ├── main.py
│       ├── context.py
│       ├── common.py
│       ├── stats_worker.py
│       └── plugins/
│           ├── certbot.py
│           ├── cron.py
│           ├── ftp.py
│           ├── mail.py
│           ├── mariadb.py
│           ├── panel.py
│           ├── php.py
│           ├── proxy.py
│           ├── security.py
│           ├── servercfg.py
│           ├── services.py
│           ├── site.py
│           ├── site_backup.py
│           └── wireguard.py
├── install/
│   ├── install.sh
│   ├── upgrade.sh
│   ├── repair.sh
│   └── lib.sh
├── sql/
│   ├── panel_schema.sql
│   └── mail_schema.sql
└── ui/
    ├── dashboard.php
    ├── sites.php
    ├── site.php
    ├── db.php
    ├── ftp.php
    ├── certbot.php
    ├── cron.php
    ├── php.php
    ├── mail.php
    ├── mail_server.php
    ├── wireguard.php
    ├── security.php
    ├── firewall.php
    ├── ufw.php
    ├── jobs.php
    ├── logs.php
    ├── api_tokens.php
    ├── api_explorer.php
    ├── server_config.php
    ├── panel_config.php
    ├── settings.php
    ├── language_editor.php
    ├── style.css
    └── language/
```

## Instalace z Git repozitáře

ORIScore WebPANEL lze nainstalovat přímo z Git repozitáře. Tento postup je vhodný pro čistý server, testovací instalaci i budoucí aktualizace přes `git pull`.

### 1. Příprava systému

Na čistém Debian/Ubuntu serveru nejdříve aktualizujte systém a nainstalujte základní nástroje:

```bash
apt update
apt upgrade -y
apt install -y git curl ca-certificates sudo
```

### 2. Stažení repozitáře

Projekt se standardně instaluje do adresáře `/opt/oris_webserver`:

```bash
cd /opt
git clone https://github.com/justich1/ORIScore-WebPANEL.git oris_webserver
cd /opt/oris_webserver
```

### 3. Spuštění instalátoru

Instalace se spouští z adresáře projektu:

```bash
chmod +x install/install.sh
chmod +x install/repair.sh
chmod +x install/upgrade.sh
chmod +x install/lib.sh
./install/install.sh
```

Instalátor provede zejména:

- instalaci balíčků,
- vytvoření databází,
- vytvoření admin účtu,
- nasazení PHP UI do `/var/www/oris-panel`,
- vytvoření `ui/config.php`,
- nastavení Nginxu,
- nastavení PHP-FPM socketu,
- nastavení vsftpd,
- nastavení phpMyAdmin snippetu,
- nastavení základního UFW/Fail2ban prostředí,
- instalaci Python backendu,
- vytvoření `/etc/oris-panel/provisioner.json`,
- vytvoření systemd služeb,
- spuštění provisioneru a stats workeru.

Po instalaci vypíše adresu panelu, phpMyAdmin a přihlašovací e-mail.

## Upgrade

```bash
sudo bash install/upgrade.sh
```

Upgrade používá stejnou projektovou strukturu a aktualizuje soubory panelu/backendu podle aktuálního archivu.

## Oprava instalace

```bash
sudo bash install/repair.sh
```

Repair script je určený pro opravu instalace, socketů, služeb nebo konfigurací po ručních zásazích.

## Důležité cesty

| Cesta | Popis |
|---|---|
| `/var/www/oris-panel` | produkční umístění PHP panelu |
| `/opt/oris_webserver` | doporučené umístění zdrojového projektu |
| `/etc/oris-panel/provisioner.json` | konfigurace Python provisioneru |
| `/var/www/sites` | výchozí adresář webů |
| `/var/lib/oris-core/uploads` | staging uploadů pro restore/import |
| `/var/lib/oris-core/wireguard` | WireGuard klientské konfigurace a QR |
| `/var/www/letsencrypt` | ACME webroot |
| `/var/vmail` | maildir úložiště |
| `/var/log/oris-core/provisioner-python.log` | log Python provisioneru |
| `/var/log/oris-security.log` | bezpečnostní log pro ORIS/Fail2ban |

## Systemd služby

Instalace vytváří/počítá hlavně s těmito službami:

```text
oris-provisioner.service
oris-stats-worker.service
nginx
php*-fpm
mariadb
vsftpd
postfix
dovecot
rspamd
redis-server
fail2ban
ufw
wg-quick@wg0
cron
```

Stavy a akce služeb lze řešit i z panelu přes stránku Systém/Služby.

## Provisioner a fronta úloh

PHP panel neprovádí systémové změny přímo. Místo toho ukládá požadavky do tabulky:

```text
jobs
```

Python provisioner běží jako služba a zpracovává joby podle typu. Výsledek je uložený zpět do databáze včetně stavu, chyby a logu.

Příklady typů jobů:

```text
provision_site
deprovision_site
site_ensure_db
ftp_create
ftp_reset_pass
certbot_issue
provision_tunnel
php_apply_config
cron_apply
security_apply
wg_peer_create
mail_domain_apply
mailbox_apply
service_action
```

Pokud typ jobu nemá hotový plugin, fallback stub zapíše do logu, že funkce je zatím v přípravě.

## Databáze

Panel používá dvě hlavní databáze:

```text
oris_panel
oris_mail
```

`oris_panel` obsahuje uživatele, nastavení, weby, proxy tunely, FTP účty, joby, API tokeny, WireGuard peery, cron úlohy a bezpečnostní události.

`oris_mail` obsahuje mail domény, mailboxy, aliasy a DKIM informace.

Schémata jsou v:

```text
sql/panel_schema.sql
sql/mail_schema.sql
```

## Konfigurace

Ukázkový soubor:

```text
ui/config.sample.php
```

Produkční konfigurace:

```text
/var/www/oris-panel/config.php
```

Základní struktura:

```php
<?php
return [
  'db' => ['host'=>'127.0.0.1','port'=>3306,'name'=>'oris_panel','user'=>'oris_panel','pass'=>'CHANGE_ME'],
  'mail_db' => ['host'=>'127.0.0.1','port'=>3306,'name'=>'oris_mail','user'=>'oris_mail','pass'=>'CHANGE_ME'],
  'db_admin' => ['user'=>'root','pass'=>'CHANGE_ME'],
  'session_name' => 'oris_panel',
  'default_lang' => 'cs',
  'langs' => ['cs','en','de','sk'],
];
```

## Bezpečnostní poznámky

- Panel pracuje se systémovou konfigurací, proto ho nedávej veřejně bez HTTPS, silného hesla a firewallu.
- `config.php` má obsahovat citlivé údaje a nemá být veřejně čitelný.
- Provisioner config `/etc/oris-panel/provisioner.json` má být dostupný jen rootovi.
- Před obnovou webů nebo mail serveru vždy zálohuj data.
- Před nasazením na produkci zkontroluj Nginx konfiguraci příkazem `nginx -t`.
- Certbot/Let’s Encrypt má rate limity, opakované chybné pokusy je lepší testovat přes staging/dry-run.


## Licence

MIT
