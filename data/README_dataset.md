# Jeu de donnees : CIC-IDS2017

- Source : Canadian Institute for Cybersecurity (UNB), https://www.unb.ca/cic/datasets/ids-2017.html
- Archive utilisee : `GeneratedLabelledFlows.zip` (dossier `TrafficLabelling`), 8 fichiers CSV
- Licence / conditions d'utilisation : a verifier sur la page officielle avant publication
  (usage academique ; citer Sharafaldin, Lashkari, Ghorbani, ICISSP 2018).
- Type d'enregistrement : **flux** (et non paquets). Les debits sont exprimes en flux/s.
- Periode couverte : du 2017-07-03 08:55 au 2017-07-07 17:02 (fuseau non precise par la source).

## Volumes (mesures par l'application)
- Lignes lues : 3 119 345
- Enregistrements valides : 2 830 743
- Lignes vides (uniquement des virgules) : 288 602
- Lignes invalides : 0
- Labels : 15 classes (BENIGN 2 273 097, DoS Hulk 231 073, PortScan 158 930, DDoS 128 027, ...)

## Champs utilises (index de colonne, base 0)
| Champ interne | Colonne CSV | Index |
|---|---|---|
| src_ip | Source IP | 1 |
| src_port | Source Port | 2 |
| dst_ip | Destination IP | 3 |
| dst_port | Destination Port | 4 |
| protocol | Protocol | 5 |
| timestamp | Timestamp | 6 |
| packets | Total Fwd Packets + Total Backward Packets | 8 + 9 |
| size_bytes | Total Length of Fwd Packets + Total Length of Bwd Packets | 10 + 11 |
| label | Label | derniere colonne |

La colonne `Fwd Header Length` apparait deux fois dans l'en-tete : les colonnes sont lues par position.

## Traitements et choix a documenter
- Format de date : JJ/MM/AAAA H:MM (avec ou sans secondes). Aucune indication AM/PM : une heure
  < 8 est interpretee comme l'apres-midi (+12 h), car le jeu ne contient pas de trafic avant 8 h.
- Les valeurs numeriques peuvent etre decimales ou en notation scientifique (fichier Monday).
- Les octets comptes sont des octets de charge utile (en-tetes exclus).
- Ports : consideres seulement pour TCP (6) et UDP (17). Seules les adresses IPv4 sont supportees.
- Aucun flux ICMP n'a ete observe ; 1 696 flux d'un autre protocole sont regroupes dans "Autres".
- Caracteres non ASCII dans les labels (« – » des Web Attack) remplaces par « - ».
- Certains flux apparaissent dans les deux sens (reponse du serveur enregistree comme un flux a part,
  labellisee BENIGN) : cela cree des faux positifs de detection de scan (voir rapport).
- Jeu de benchmark : tailles <= 2,83 M obtenues par echantillonnage systematique ;
  la taille 5 M repete le jeu complet avec decalage temporel (donnees repliquees, non independantes).
