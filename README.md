# bq-watchdog

Moniteur de sécurité Linux léger — détecte les IoCs connus, les dérives de config SSH, les binaires suspects et les connexions malveillantes. Alerte via webhook Discord.

## Installation rapide

```bash
curl -fsSL https://github.com/BugQuest/bq-watchdog/releases/latest/download/install.sh | sudo bash
```

L'installeur :
- Télécharge la dernière release
- Configure le webhook Discord
- Installe un cron (toutes les 30 min par défaut)
- Lance un premier audit immédiatement

## Checks inclus

| # | Check | Description |
|---|-------|-------------|
| 01 | IoC color1337 | Clé SSH backdoor ElPatrono1337, fichiers malveillants Diicot, C2 connus |
| 02 | Config SSH | PasswordAuthentication, cloud-init override, PermitRootLogin |
| 03 | Crontabs | Patterns malveillants (curl\|bash, /var/tmp, base64...) |
| 04 | Fichiers temp | Binaires ELF dans /tmp /var/tmp /dev/shm, répertoires cachés |
| 05 | Users/clés SSH | Comptes suspects, clés aux noms suspects, root+password+SSH |
| 06 | Réseau | Connexions vers IPs/ports malveillants connus (C2, stratum mining) |
| 07 | Processus | Noms hex obfusqués, exécution depuis /tmp, mineurs connus |

## Configuration manuelle

```bash
cp /opt/bq-watchdog/config.example /opt/bq-watchdog/config
nano /opt/bq-watchdog/config
```

## Lancer manuellement

```bash
sudo /opt/bq-watchdog/watchdog.sh
```

## Logs

```bash
tail -f /var/log/bq-watchdog.log
```

## Codes de sortie

| Code | Signification |
|------|---------------|
| 0 | Propre |
| 2 | Findings détectés |

## Ajouter un check

Créer `checks/08-mon-check.sh` avec une fonction `check_mon_check()` — elle est chargée automatiquement.

```bash
check_mon_check() {
    # finding <warning|critical> "titre" "détail"
    if [[ -f /un/fichier/suspect ]]; then
        finding critical "Fichier suspect trouvé" "Chemin: /un/fichier/suspect"
    fi
}
```

## Références

- [Analyse de la campagne color1337 / ElPatrono1337 — Invirtuate](https://invirtuate.com/blog/incidents/ElPatrono1337-color1337-cryptomining-attack)
- [Autopsie d'une infection VPS — BugQuest](https://bugquest.fr/projects/vps-infection-xmrig)
