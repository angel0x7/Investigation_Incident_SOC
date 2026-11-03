#  Rapport d'incident cybersécurité – Investigation PC01 / SRV01 / AD01

> Projet **SOC – Fondamentaux** · ECE École d'Ingénieurs · 2026
> Analyse forensique des journaux Windows d'une compromission ayant abouti au **chiffrement d'un contrôleur de domaine** par un ransomware.

---

##  Sommaire

- [Contexte](#-contexte)
- [Périmètre](#-périmètre)
- [Méthodologie et outils](#-méthodologie-et-outils)
- [Synthèse de l'attaque](#-synthèse-de-lattaque)
- [Techniques MITRE ATT&CK](#-techniques-mitre-attck-observées)
- [Indicateurs de compromission](#-indicateurs-de-compromission-principaux)
- [Remédiation](#-remédiation)
- [Recommandations](#-recommandations)
- [Structure du dépôt](#-structure-du-dépôt)
- [Reproduire l'analyse](#-reproduire-lanalyse)
- [Équipe](#-équipe)

---

##  Contexte

L'entreprise fictive **Benarfacorp** (domaine `benarfacorp.local`) a vu son contrôleur de domaine chiffré par un ou plusieurs attaquants, accompagné d'une demande de rançon.

Le périmètre se limite à un VLAN de trois machines. Un développeur a pu extraire les journaux Windows de chacune avant leur extinction. L'entreprise utilise légitimement **AnyDesk** pour l'administration, ce qui complique la distinction entre usage légitime et malveillant.

**Objectif du projet** : rédiger un rapport d'investigation complet, présentable à un client final, qui permet de :

- reconstituer les activités suspectes sur chaque machine ;
- identifier les outils et commandes utilisés par l'attaquant ;
- détecter les traces d'accès aux identifiants, d'élévation de privilèges et de persistance ;
- évaluer l'impact et proposer un plan de remédiation.

##  Périmètre

| Hôte | IP | Rôle | Fonction |
|------|----|------|----------|
| `AD01.benarfacorp.local` | 192.168.206.49 | Contrôleur de domaine | Active Directory & authentification |
| `SRV01.benarfacorp.local` | 192.168.206.50 | Serveur applicatif | Services applicatifs |
| `PC01.benarfacorp.local` | 192.168.206.51 | Poste développeur | Poste de travail |

**Sources analysées** (fichiers `.evtx` pour chaque machine) : `Application`, `PowerShellOperational`, `Security`, `Sysmon`, `System`, `WindowsPowerShell`.


##  Méthodologie et outils

| Outil | Usage |
|-------|-------|
| [EvtxECmd](https://github.com/EricZimmerman/evtx) | Conversion des `.evtx` en CSV pour parsing |
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw) | Hunting sur les journaux avec règles Sigma |
| [SigmaHQ](https://github.com/SigmaHQ/sigma) | Règles de détection |
| [MITRE ATT&CK](https://attack.mitre.org/) | Cartographie des TTPs |

##  Synthèse de l'attaque

L'ensemble de la compromission s'est déroulée en **un peu plus d'une heure** (15:08 → 16:14, UTC+2), en neuf phases.

| Phase | Hôte / Compte | Heure | Action |
|-------|---------------|-------|--------|
| 1. Compromission initiale | PC01 · `Administrateur` | 15:08 | Ouverture de `GTA6_cheats_list.docm` (macro) → **reverse shell** PowerShell vers `192.168.206.25:4444` |
| 2. Prise de contrôle & reconnaissance | PC01 | 15:09 – 15:13 | Désactivation de Windows Defender, énumération AD (`net group`, `nltest`, `whoami /all`…) |
| 3. Vol d'identifiants | PC01 | 15:16 – 15:19 | Téléchargement et exécution de **Mimikatz** (`mz.exe`) |
| 4. Mouvement latéral | SRV01 | 15:21 | Déploiement de **RemCom** (exécution à distance type PsExec) |
| 5. Collecte d'identifiants | SRV01 | 15:22 – 15:26 | Defender désactivé, dump LSASS via **ProcDump**, export des ruches SAM/SECURITY/SYSTEM, analyse Mimikatz |
| 6. Compromission du domaine | AD01 · `superadmin` | 15:52 | Connexion NTLM, nouveau RemCom, activation du **RDP**, pare-feu désactivé |
| 7. Collecte & exfiltration | AD01 | 15:55 – 16:02 | `ntdsutil` (copie de `ntds.dit`), ruches, certificats, tickets Kerberos, archive `data.zip` envoyée en HTTP POST vers `192.168.206.25:8000` |
| 8. Persistance | AD01 | 16:06 – 16:11 | Compte Domain Admin `svcupdate`, **AnyDesk** déployé via une GPO nommée `backup` |
| 9. Impact | AD01 | 16:14 | Script `outerwilds.ps1` : chiffrement (`.locked`) et dépôt de `README_DECRYPT.txt` |

##  Techniques MITRE ATT&CK observées

| Tactique | Techniques |
|----------|-----------|
| Exécution | T1059.001 (PowerShell), T1569.002 (System Services) |
| Persistance | T1136.002 (Domain Account), T1098 (Account Manipulation), T1219 (Remote Access Software) |
| Évasion de défense | T1562.001 (Impair Defenses), T1036 (Masquerading) |
| Accès aux identifiants | T1003.001 (LSASS), T1003.002 (SAM), T1003.003 (NTDS), T1003.004 (LSA Secrets) |
| Découverte | T1082, T1033, T1069, T1016 |
| Mouvement latéral / Accès | T1078 (Valid Accounts) |
| Collecte & Exfiltration | T1560.001 (Archive via Utility), T1041 (Exfiltration over C2) |
| Command & Control | T1105 (Ingress Tool Transfer) |

##  Indicateurs de compromission principaux

| Type | Indicateur |
|------|-----------|
| IP (attaquant, interne) | `192.168.206.25` (ports 4444, 8000, HTTP) |
| URL | `http://192.168.206.25/mimikatz.exe` |
| Fichiers | `C:\temp\mz.exe`, `C:\temp\procdump.exe`, `C:\temp\procdump64.exe`, `C:\temp\lsass.dmp`, `C:\temp\data.zip`, `C:\temp\certs.cer` |
| Exécutables RemCom | `C:\Windows\tsLLfuld.exe` (SRV01), `C:\Windows\NMBrkygM.exe` (AD01) |
| Pipes nommés | `\RemCom_communicaton` |
| Comptes | `svcupdate` (créé par l'attaquant), `BENARFACORP\superadmin` (compromis) |
| Outils | `ntdsutil.exe`, AnyDesk, GPO `backup`, script `deploy_anydesk.bat` |
| Ransomware | `outerwilds.ps1`, extension `.locked`, `README_DECRYPT.txt` |

SHA256 commun aux deux exécutables RemCom (même binaire renommé) :

```
3C2FE308C0A563E06263BBACF793BBE9B2259D795FCC36B953793A7E499E7F71
```

La liste complète (avec hashs) est disponible dans la section 7 du rapport.

##  Remédiation

1. **Confinement** : préserver les preuves, isoler PC01 et SRV01, confinement contrôlé d'AD01, bloquer les flux vers `192.168.206.25`.
2. **Éradication** : supprimer `svcupdate`, les services RemCom, la GPO `backup`, les outils et dumps ; réinitialiser tous les mots de passe.
3. **Réinitialisation de `krbtgt` (deux fois)** : indispensable après le vol de `ntds.dit` pour invalider tout Golden Ticket.
4. **Restauration** : reconstruction d'AD01 depuis une sauvegarde saine, réinstallation de PC01 et SRV01, réintégration progressive sous surveillance renforcée.
5. **Rétablissement des défenses** : Defender, Credential Guard, WDigest, désactivation du RDP.

##  Recommandations

- **AD / Identités** : audit des comptes privilégiés et des GPO, MFA sur les accès admin, séparation comptes bureautiques / privilégiés.
- **Protection des identifiants** : protection LSASS, Credential Guard, détection des dumps.
- **Endpoint** : protection anti-altération Defender, alertes sur les changements de registre et arrêts de service.
- **Journalisation** : centralisation externalisée, Script Block Logging PowerShell.
- **Réseau** : segmentation postes / serveurs / DC, surveillance des ports non standards.
- **Authentification** : abandon de NTLMv1.
- **Exécution** : liste blanche (WDAC / AppLocker), autoriser uniquement les outils d'accès distant approuvés.

##  Structure du dépôt

```
.
├── README.md
├── docs/
│   ├── Rapport_Incident_Cybersecurite.pdf   # Rapport complet
│   └── SOC-Fundamentals_Projet.docx         # Énoncé du projet
└── logs/                                    # (optionnel) .evtx / CSV, non versionnés
    ├── AD01/
    ├── SRV01/
    └── PC01/
```

>  Les journaux bruts peuvent contenir des données sensibles : pensez à les ajouter au `.gitignore` si le dépôt est public.

##  Reproduire l'analyse

**1. Conversion des journaux `.evtx` en CSV (EvtxECmd)**

```powershell
.\EvtxECmd.exe -d "C:\Projet\AD01"  --csv "C:\Projet\AD01csv"
.\EvtxECmd.exe -d "C:\Projet\PC01"  --csv "C:\Projet\PC01csv"
.\EvtxECmd.exe -d "C:\Projet\SRV01" --csv "C:\Projet\SRV01csv"
```

**2. Détection Sigma avec Chainsaw**

```powershell
.\chainsaw.exe hunt "C:\Projet\<systeme>" `
  -s "C:\sigma-master\rules" `
  --mapping ".\mappings\sigma-event-logs-all.yml" `
  --csv --output "C:\Projet\<systeme>_Result_csv_from_chainsaw"
```

**3. Corrélation** : analyse des CSV (Timeline Explorer, Excel, etc.) autour des Event IDs clés : Security `4688` / `4624`, PowerShell `4104`, Sysmon `1`, `11`, `17`.

##  Équipe

Projet réalisé par **Sourdin · Adda · Velasco · Marchal**
ECE École d'Ingénieurs · SOC – 2026

---

*Projet académique à but pédagogique. Tous les noms d'entreprise, hôtes et comptes sont fictifs.*
