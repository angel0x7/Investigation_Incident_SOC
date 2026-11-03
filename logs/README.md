#  Journaux Windows

Ce dossier est destiné aux journaux d'événements Windows (`.evtx`) des trois machines analysées, ainsi qu'à leurs conversions en CSV.

## Organisation

logs/
├── AD01/    # Contrôleur de domaine (192.168.206.49)
├── SRV01/   # Serveur applicatif (192.168.206.50)
└── PC01/    # Poste développeur (192.168.206.51)

Chaque dossier contient les fichiers `.evtx` suivants : `Application`, `PowerShellOperational`, `Security`, `Sysmon`, `System`, `WindowsPowerShell`.

## Traitement

1. Conversion `.evtx` vers CSV avec **EvtxECmd**.
2. Détection avec **Chainsaw** et les règles **Sigma**.

Les commandes exactes sont dans l'annexe A du rapport et dans le README principal.
