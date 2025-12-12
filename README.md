# -Marauder-Pi-Raspberry-Pi-5-Edition-Nexmon-

Marauder-Pi est une interface graphique inspirée d’ESP32 Marauder, conçue pour fonctionner sur Raspberry Pi, avec écran TFT, et orientée reconnaissance Wi-Fi et expérimentation Nexmon.

Cette édition est spécifiquement adaptée au Raspberry Pi 5, en tenant compte des limitations actuelles du Wi-Fi interne Broadcom.

⚠️ Avertissement légal

Ce projet est destiné à :

l’apprentissage,

la recherche,

l’audit de réseaux dont vous êtes propriétaire ou autorisé.

Toute utilisation illégale est strictement interdite.
L’auteur n’est responsable d’aucune mauvaise utilisation.

🧠 Architecture du projet (Pi 5)
Raspberry Pi 5
│
├── Wi-Fi interne (Broadcom BCM4389)
│   └── Nexmon (monitor / injection expérimentale)
│
├── Interface graphique (Python / Tkinter)
│   └── Écran TFT SPI (ILI9341 / Joy-IT)
│
└── Modules Marauder
    ├── Scan Wi-Fi (passif)
    ├── Sélection de cibles
    ├── Status Nexmon / capacités
    └── Attaques (désactivées ou limitées sur Pi 5)

✅ Fonctionnalités supportées sur Pi 5
✔️ Fonctionnel

Scan Wi-Fi passif (beacons, SSID, BSSID, canal)

Sélection de cible

Interface tactile / écran TFT

Détection automatique des capacités Wi-Fi

Mode “Recon / Monitor”

Interface prête pour clé USB externe

⚠️ Limité (état actuel)

Injection Wi-Fi instable

Deauth / attaques actives non fiables

Incompatibilité avec aireplay-ng / aircrack-ng

👉 Ces limites sont liées au matériel et aux drivers Broadcom BCM4389, pas au code.

❌ Non supporté sur Pi 5 (actuellement)

aireplay-ng

PMKID avec outils classiques

Attaques aircrack-ng

Injection kernel-level stable

🔍 Pourquoi ces limitations ?

Le Raspberry Pi 5 utilise un chipset Broadcom BCM4389 (Wi-Fi 6).

Nexmon pour BCM4389 est encore expérimental

Les outils aircrack-ng ne savent pas dialoguer avec Nexmon

Le driver ne fournit pas l’interface requise pour l’injection classique

➡️ Le projet est donc volontairement limité à un mode passif / expérimental sur Pi 5.

🧩 Mode recommandé sur Pi 5
🔵 Mode “Recon / Demo”

Scan en continu

Affichage réseaux

Sélection cible

Interface stable sur écran TFT

Préparation à l’attaque (sans exécution)

🟢 Mode “Full” (optionnel)

Ajouter une clé USB Wi-Fi compatible injection (Alfa, etc.)

Marauder-Pi détecte automatiquement wlan1

Attaques activées sans modifier le code

🔌 Matériel recommandé
Obligatoire

Raspberry Pi 5

Carte SD ≥ 16 Go

Écran TFT SPI (ILI9341 / Joy-IT RB-TFT3.2)

Alimentation stable

Optionnel (pour attaques complètes)

Clé Wi-Fi USB compatible injection :

Alfa AWUS036NHA

Alfa AWUS036ACM

Panda PAU09

🖥️ Interface graphique

Résolution adaptée aux écrans TFT

Plein écran

Console scrollable

Boutons dynamiques (activés/désactivés selon capacités)

Statut clair :
Injection supportée / non supportée

🔄 Compatibilité matérielle
Plateforme	État
Raspberry Pi 5	⚠️ Recon uniquement
Raspberry Pi 3B+	✅ Nexmon complet
Pi 5 + clé Alfa	✅ Complet
Pi 3B+ + Nexmon	✅ Recommandé
🚀 Évolution prévue

Mode hybride Nexmon / USB

Sélecteur d’interface Wi-Fi

Support Pi 3B+ optimisé

Amélioration tactile

Logs avancés

🧠 Conseil important

Si ton objectif est un Marauder pleinement fonctionnel,
privilégie :

Pi 3B+ + Nexmon, ou

Pi 5 + clé Wi-Fi USB compatible injection

📜 Licence

Projet open-source — usage éducatif uniquement.
