#!/usr/bin/env python3
# hashsight.py
# Prototype HashSight - identification heuristique de hash + suggestions Hashcat
# Usage: python3 hashsight.py "<hash_string>"

import sys
import math
import re
from collections import Counter


print("""██╗  ██╗ █████╗ ███████╗██╗  ██╗██╗  ██╗   ██╗
██║  ██║██╔══██╗██╔════╝██║  ██║██║  ╚██╗ ██╔╝
███████║███████║███████╗███████║██║   ╚████╔╝ 
██╔══██║██╔══██║╚════██║██╔══██║██║    ╚██╔╝  
██║  ██║██║  ██║███████║██║  ██║███████╗██║   
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝   """)
# ===== utilitaires =====


def detect_hash_algorithms(hash_str):
    """
    Détecte les algorithmes de hachage possibles pour une chaîne de hash donnée.
    Retourne une liste de dictionnaires {name, mode, confidence} triés par probabilité décroissante.
    """
    candidates = []

    # 1. Détection par motifs spécifiques (formats avec préfixes connus)
    if re.match(r'^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$', hash_str):
        candidates.append({"name": "BCrypt (Blowfish)", "mode": 3200, "confidence": 100})
    elif re.match(r'^\$1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}$', hash_str):
        candidates.append({"name": "MD5-Crypt (Unix)", "mode": 500, "confidence": 100})
    elif re.match(r'^\$5\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{43}$', hash_str):
        candidates.append({"name": "SHA-256 Crypt (Unix)", "mode": 7400, "confidence": 100})
    elif re.match(r'^\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$', hash_str):
        candidates.append({"name": "SHA-512 Crypt (Unix)", "mode": 1800, "confidence": 100})
    elif re.match(r'^\$apr1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}$', hash_str):
        candidates.append({"name": "MD5 (Apache apr1)", "mode": 1600, "confidence": 100})
    elif re.match(r'^\$[PH]\$[./0-9A-Za-z]{31}$', hash_str):
        # PHPass portable (WordPress ≥2.6.2 uses $P$, phpBB3 uses $H$)
        candidates.append({"name": "PHPass (WordPress/Joomla)", "mode": 400, "confidence": 100})
    elif re.match(r'^\*[0-9A-F]{40}$', hash_str):
        # MySQL 4.1+ double SHA-1 hash (usually stored with a leading '*')
        candidates.append({"name": "MySQL 4.1/5 (double SHA-1)", "mode": 300, "confidence": 100})
    elif len(hash_str) == 13 and re.match(r'^[./0-9A-Za-z]{13}$', hash_str):
        # Traditional DES crypt (2-char salt + 11-char hash = 13 chars)
        candidates.append({"name": "DES (Unix)", "mode": 1500, "confidence": 100})

    # 2. Si aucun motif unique n'a été trouvé, on passe à la déduction par longueur/format
    if not candidates:
        # a) Cas des chaînes hexadécimales (0-9 & A-F)
        if re.match(r'^[0-9A-Fa-f]+$', hash_str):
            hex_len = len(hash_str)
            is_upper = hash_str.isupper()  # toute en majuscules (souvent indicatif d'origine Windows)

            if hex_len == 32:
                # 32 hex = 128 bits -> MD5, NTLM, etc.
                # On ajuste la confiance selon la casse (minuscule => MD5 plus probable, majuscule => NTLM plus probable)
                md5_conf = 50
                ntlm_conf = 40
                if is_upper:
                    md5_conf = 40
                    ntlm_conf = 50
                candidates.append({"name": "MD5 (128-bit)", "mode": 0, "confidence": md5_conf})
                candidates.append({"name": "NTLM (Windows MD4)", "mode": 1000, "confidence": ntlm_conf})
                candidates.append({"name": "MD4 (128-bit, peu utilisé)", "mode": 900, "confidence": 5})
                # Détection d'un éventuel hash LM (si la seconde moitié du hash est la constante vide)
                if hash_str[16:].upper() == "AAD3B435B51404EE":
                    candidates.append({"name": "LM (LanManager - ancien Windows)", "mode": 3000, "confidence": 5})

            elif hex_len == 40:
                # 40 hex = 160 bits -> SHA-1, MySQL double SHA1, RIPEMD-160...
                candidates.append({"name": "SHA-1 (160-bit)", "mode": 100, "confidence": 70})
                candidates.append({"name": "MySQL 4.1/5 double SHA-1", "mode": 300, "confidence": 20})
                candidates.append({"name": "RIPEMD-160 (160-bit)", "mode": 6000, "confidence": 10})

            elif hex_len == 16:
                # 16 hex = 64 bits -> ancien hash MySQL?
                candidates.append({"name": "MySQL323 (Ancien format MySQL)", "mode": 200, "confidence": 100})

            elif hex_len == 56:
                # 56 hex = 224 bits
                candidates.append({"name": "SHA-224 (224-bit)", "mode": 1300, "confidence": 100})

            elif hex_len == 64:
                # 64 hex = 256 bits
                candidates.append({"name": "SHA-256 (256-bit)", "mode": 1400, "confidence": 90})
                candidates.append({"name": "SHA3-256 (256-bit)", "mode": 5000, "confidence": 5})
                candidates.append({"name": "RIPEMD-256 (256-bit)", "mode": None, "confidence": 5})

            elif hex_len == 96:
                # 96 hex = 384 bits
                candidates.append({"name": "SHA-384 (384-bit)", "mode": 10800, "confidence": 90})
                candidates.append({"name": "SHA3-384 (384-bit)", "mode": None, "confidence": 10})

            elif hex_len == 128:
                # 128 hex = 512 bits
                candidates.append({"name": "SHA-512 (512-bit)", "mode": 1700, "confidence": 70})
                candidates.append({"name": "Whirlpool (512-bit)", "mode": 6100, "confidence": 30})

            else:
                # Longueur inhabituelle
                candidates.append({"name": "Format non reconnu (longueur {} caractères)".format(hex_len),
                                   "mode": None, "confidence": 0})

        # b) Cas des chaînes encodées en Base64
        elif re.match(r'^[A-Za-z0-9+/]+={0,2}$', hash_str):
            b64_len = len(hash_str)
            if hash_str.endswith("=="):
                if b64_len == 24:
                    candidates.append({"name": "Hash MD5 (Base64)", "mode": 0, "confidence": 100})
                elif b64_len == 88:
                    candidates.append({"name": "Hash SHA-512 (Base64)", "mode": 1700, "confidence": 100})
            elif hash_str.endswith("="):
                if b64_len == 28:
                    candidates.append({"name": "Hash SHA-1 (Base64)", "mode": 100, "confidence": 100})
                elif b64_len == 44:
                    candidates.append({"name": "Hash SHA-256 (Base64)", "mode": 1400, "confidence": 100})
                elif b64_len == 64:
                    candidates.append({"name": "Hash SHA-384 (Base64)", "mode": 10800, "confidence": 100})
            else:
                if b64_len == 64:
                    candidates.append({"name": "Hash SHA-384 (Base64)", "mode": 10800, "confidence": 100})
                else:
                    candidates.append({"name": "Hash inconnu (Base64)", "mode": None, "confidence": 0})
        else:
            # Ni hex ni base64 -> format inconnu
            candidates.append({"name": "Format de hash non reconnu", "mode": None, "confidence": 0})

    # Trier les candidats par confiance décroissante
    candidates.sort(key=lambda x: x["confidence"], reverse=True)
    return candidates

# --- Programme principal ---
print("===== Identification de Hash =====")
user_hash = input("Entrez le hash à identifier : ").strip()

# Détection des algorithmes possibles
algos = detect_hash_algorithms(user_hash)

# Affichage des résultats
if not algos:
    print("Aucun algorithme correspondant n’a été trouvé.")
else:
    if len(algos) == 1:
        # Un seul algorithme probable
        algo = algos[0]
        print(f"\nHash identifié comme : {algo['name']} (confiance {algo['confidence']}%)")
    else:
        # Plusieurs candidats trouvés
        print("\nAlgorithmes possibles pour ce hash :")
        for i, algo in enumerate(algos, start=1):
            name = algo['name']
            conf = algo['confidence']
            print(f"  {i}. {name} – confiance estimée {conf}%")
        # Demander à l'utilisateur de choisir
        choice = None
        while choice is None:
            try:
                choice = int(input("Veuillez indiquer le numéro de l'algorithme correct selon vous : "))
                if choice < 1 or choice > len(algos):
                    print(f"Entrez un nombre entre 1 et {len(algos)}.")
                    choice = None
            except ValueError:
                print("Veuillez entrer un numéro valide.")
                choice = None
        algo = algos[choice - 1]
        print(f"\nAlgorithme sélectionné : {algo['name']}")

    # Suggestion de commandes Hashcat si mode disponible
    if 'algo' in locals() and algo.get('mode') is not None:
        mode = algo['mode']
        print("\n----- Suggestions de commande Hashcat -----")
        # Wordlist attack with rockyou
        print(f"[*] Attaque dictionnaire (rockyou.txt) : hashcat -m {mode} -a 0 -o résultats.txt hash.txt rockyou.txt")
        # Brute-force attack example
        print(f"[*] Attaque brute-force : hashcat -m {mode} -a 3 hash.txt ?a?a?a?a")
        print("    (Remplacez ?a?a?a?a par un masque adapté à la longueur/type de votre mot de passe.)")
    else:
        print("\nDésolé, aucun mode Hashcat disponible pour ce type de hash.")
