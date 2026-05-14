# chabahroot

Plateforme unifiee de supervision comportementale du noyau Linux.

---

## Vue d'ensemble

`chabahroot` est un script shell de supervision de securite systeme concu pour les environnements Linux. Il integre en un seul executable trois fonctionnalites complementaires :

- **M1 - Capture noyau** : activation des tracepoints Linux via le systeme de fichiers `tracefs`, capture des appels systeme critiques (`execve`, `setuid`, `setgid`, `prctl`) et emission d'un flux d'evenements bruts.
- **M3 - Normalisation** : decodage, enrichissement, filtrage des donnees sensibles et normalisation des evenements bruts en objets JSON canoniques.
- **M2 - Detection comportementale** : moteur de regles base sur un fichier `detection_rules.json`, evaluation de conditions `jq` sur chaque evenement normalise, generation d'alertes et execution d'actions configurables.

Un mode defensif complementaire surveille en continu les escalades de privileges par interrogation periodique de la table des processus, et un mode offensif effectue un audit statique du systeme (binaires SUID non standards, fichiers accessibles en ecriture par tous, regles `sudoers` risquees).

---

## Prerequis

### Systeme d'exploitation

- Linux avec noyau >= 4.1 (support `tracefs`)
- Shell : `bash` >= 4.4

### Privileges

Certaines fonctionnalites requierent des privileges root :

| Fonctionnalite | Privilege requis |
|---|---|
| Activation des tracepoints (`live`, `capture-start`) | root |
| Reinitialisation de l'etat (`-r`) | root |
| Audit offensif complet | root (recommande) |
| Pipeline sur corpus d'exemples | aucun |

### Dependances externes

| Outil | Usage |
|---|---|
| `jq` | Traitement JSON (normalisation, detection, filtrage) |
| `ps` | Surveillance des processus (mode defensif) |
| `find` | Audit du systeme de fichiers (mode offensif) |
| `uuidgen` | Generation d'identifiants d'alertes (facultatif, repli RANDOM si absent) |

Installation des dependances sur les distributions Debian/Ubuntu :

```bash
sudo apt-get install jq util-linux
```

Sur les distributions Red Hat/Fedora :

```bash
sudo dnf install jq util-linux
```

---

## Installation

### Clonage du depot

```bash
git clone <url-du-depot> chabahroot
cd chabahroot
```

### Donnees requises a la premiere utilisation

Le script attend les fichiers suivants par rapport a son repertoire d'installation :

```
chabahroot/
    chabahroot.sh                                          # Script principal
    chabahroot/
        vigie_comportementale/
            detection_rules.json                           # Regles de detection (obligatoire)
        socle_commun/
            rules.conf                                     # Configuration additionnelle (facultatif)
    examples/
        sample_events.ndjson                               # Corpus d'evenements pour les tests
    detection/
        tmp/
            seen_pids.tmp                                  # Fichier d'etat cree automatiquement
```

Le fichier `detection_rules.json` est obligatoire pour le demarrage du pipeline. Le corpus d'exemples `sample_events.ndjson` est necessaire pour les tests sans capture noyau active.

### Permissions d'execution

```bash
chmod +x chabahroot.sh
```

---

## Mode d'emploi

### Syntaxe generale

```
./chabahroot.sh [options] [mode_execution] [source_evenements]
./chabahroot.sh [sous-commande]
```

### Options courtes

| Option | Description |
|---|---|
| `-h` | Affiche l'aide complete |
| `-f` | Mode d'execution par fork (FIFO + sous-processus) |
| `-t` | Mode thread (alias de sequential en bash pur) |
| `-s` | Mode sous-shell isole |
| `-l <repertoire>` | Repertoire de journalisation (defaut : `/var/log/chabahroot`) |
| `-r` | Reinitialise l'etat transitoire et desactive tracefs (root requis) |

### Modes d'execution du pipeline

| Positional | Description |
|---|---|
| `sequential` | Pipeline dans le shell courant (defaut) |
| `fork` | Pipeline via FIFO et sous-processus dedie |
| `subshell` | Pipeline dans un sous-shell |
| `thread` | Alias de sequential (bash pur ne supporte pas les threads natifs) |

### Sources d'evenements

| Source | Description |
|---|---|
| `auto` | Detection automatique : variable d'environnement, puis FIFO live, puis corpus (defaut) |
| `sample` | Corpus d'exemples embarque |
| `stdin` | Lecture depuis l'entree standard |
| `live` | Capture directe tracefs (root requis) |
| `file <chemin>` | Fichier NDJSON specifique |
| `--input <chemin>` | Equivalent long de `file` |

### Filtres d'analyse

| Option | Description |
|---|---|
| `--pipeline-only` | Normalisation et detection uniquement (sans audit offensif ni defensif) |
| `--audit-only` | Audit offensif statique uniquement |

### Sous-commandes de capture

| Sous-commande | Description |
|---|---|
| `capture-start` | Active les tracepoints noyau et demarre le captureur en arriere-plan |
| `capture-stop` | Arrete le captureur et desactive les tracepoints |
| `capture-status` | Affiche l'etat courant du captureur |

---

## Exemples d'utilisation

### Execution standard sur le corpus d'exemples

```bash
./chabahroot.sh sample
```

Lance le pipeline complet (audit offensif, surveillance defensive, normalisation et detection) en utilisant le corpus d'evenements embarque. Ne requiert pas de privileges root.

### Pipeline seul sur le corpus

```bash
./chabahroot.sh --pipeline-only sample
```

### Audit offensif uniquement

```bash
sudo ./chabahroot.sh --audit-only
```

### Capture noyau en temps reel

```bash
# Demarrer la capture en arriere-plan
sudo ./chabahroot.sh capture-start

# Verifier l'etat de la capture
sudo ./chabahroot.sh capture-status

# Lancer la detection sur le flux live
sudo ./chabahroot.sh --pipeline-only auto

# Arreter la capture
sudo ./chabahroot.sh capture-stop
```

### Pipeline en mode fork avec source NDJSON specifique

```bash
./chabahroot.sh fork file /chemin/vers/evenements.ndjson
```

### Lecture depuis l'entree standard

```bash
cat evenements.ndjson | ./chabahroot.sh sequential stdin
```

### Journalisation dans un repertoire personnalise

```bash
./chabahroot.sh -l /tmp/logs_analyse sample
```

### Reinitialisation complete de l'etat

```bash
sudo ./chabahroot.sh -r
```

---

## Codes de sortie

| Code | Signification |
|---|---|
| `0` | Succes |
| `100` | Option inconnue |
| `101` | Parametre obligatoire manquant |
| `102` | Fichier requis absent |
| `103` | Privileges insuffisants |
| `104` | Commande requise absente |
| `105` | Erreur tracefs |

---

## Architecture du pipeline

Le script organise le traitement des evenements selon un pipeline en trois etapes :

```
[Noyau Linux / Corpus / Stdin]
            |
            v
    M1 : Capture tracefs
    (tracepoints : execve, setuid, setgid, prctl)
            |
            v
    M3 : Normalisation
    (decodage, enrichissement, filtrage sensible, format JSON canonique)
            |
            v
    M2 : Detection comportementale
    (evaluation des regles, generation d'alertes, actions)
            |
            v
    [alerts.ndjson / actions.log / stderr]
```

En mode `full` (defaut), la surveillance defensive et l'audit offensif sont executes en parallele du pipeline principal.

---

## Journalisation

Les journaux sont ecrits dans `/var/log/chabahroot/history.log` (ou dans le repertoire specifie par `-l`). Chaque entree suit le format :

```
AAAA-MM-JJ-HH-MM-SS : <utilisateur> : <niveau> : [<categorie>] <message>
```

Les niveaux sont : `INFOS`, `WARN`, `ALERT`, `ERROR`.

---

## Depannage

### Le script echoue avec le code 102

Le fichier `detection_rules.json` est introuvable. Verifiez que le chemin `chabahroot/vigie_comportementale/detection_rules.json` existe relativement au repertoire du script.

### Le script echoue avec le code 103

Une action privilegiee a ete tentee sans root. Relancez la commande avec `sudo`.

### Le script echoue avec le code 104

Une dependance externe est absente. Installez `jq`, `ps` et `find` (voir la section Prerequis).

### tracefs n'est pas monte

```bash
sudo mount -t tracefs tracefs /sys/kernel/tracing
```

### Les alertes ne sont pas generees

Verifiez la syntaxe du fichier `detection_rules.json` avec `jq empty detection_rules.json`. Verifiez que les champs `enabled`, `condition` et `actions` sont correctement renseignes.

### Le mode live ne capture rien

Assurez-vous que `capture-start` a ete execute avec succes (`capture-status` doit afficher un PID actif), et que la source `auto` ou `live` est bien specifiee.

---

## Securite

- Les conditions des regles de detection sont validees avant execution afin d'empecher toute injection de filtres `jq` arbitraires via un fichier `detection_rules.json` altere.
- Les champs `argv`, `cmdline` et `parent_cmdline` sont automatiquement rediges (`[REDACTED]`) si un mot-cle sensible (`password`, `token`, `secret`, `key`, `pass`) y est detecte.
- Le fichier `seen_pids.tmp` est elague a chaque cycle afin d'eviter les confusions liees au recyclage des PID Linux.

---


