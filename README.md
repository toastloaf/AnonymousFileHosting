# Sky-lagring basert på et anonymt konto nummer system for inlogging

Dette prosjektet er laget til inlevering av et python-prosjekt (brukerinput).<br>
<br>
Jeg fikk inspirasjon av Mullvad VPN, som bruker et konto nummer system for inlogging av bruker, som ikke krever et passord, brukernavn eller e-post.<br>
Koden er for mesteparten python, men det er en go del med javascript i html-filene, nettsiden er drevet ved bruk av flask modulen.<br>
<br>

## Kilder
Cookie Expiration: https://verdantfox.com/blog/cookies-with-the-flask-web-framework#cookie-expirations<br>
Få cookie fra javascript i html filene: GitHub Copilot<br>
Large filer i formData i javascript: GitHub Copilot<br>
Ideen til og bruke CORS til sending av filer: Bing Search, husker ikke linken<br>
Ideen til prosjektet: Mullvad VPN

## Kode som er laget av AI
Meste parten av fil-hashing koden på client-siden (dashboard.html) var laget av GitHub Copilot, fordi jeg fant ut at hashing coden jeg had skrevet ville ikke fungere på filer over 2GB og fungerte med og lagre filen i ram, til og fikse dette måtte jeg lage et chunk system, som er alt for komplisert for meg i javascript.

Fil hashing funksjonen git et problem med sjekking av fil størrelse, jeg brukte Github Copilot til å fikse det ved å reset fil pointeren.

JSON Response funksjonen i javascript var laget av GitHub Copilot for mesteparten.

Fil-enkrypsjon var en funksjon jeg ville lage uten bruk av AI, men etter en hel dag av problemer og feil, hadde jeg bestemt for og bare bruke GitHub Copilot til og lage mesteparten av den koden også, jeg had originalt plannet til og bruke et asymmetrisk enkrypsjon system for bedre sikkerhet, men det ville ikke fungere.<br>
Selv om jeg bruke AI for mesteparten av enkrypsjon, jeg brukte ingen AI for dekrypsjon, fordi det er ikke så avansert, jeg brukte kun AI til og lage funksjonen som lagrer den dekrypterte filen, sender den, og sletter den dekrypterte filen fra serveren, men selve dekrypsjon funksjonen var laget uten bruk av AI.

Jeg brukte også GitHub Copilot sin Autocomplete funksjon noen ganger, fordi det gjør det mye raskere og debug koden og skrive den.

## Dokumentasjon
### Bruk av nettsiden
1. Trykk på **Generate Account** på inlogging siden hvis du skal lage en ny konto.
2. Kopier konto-nummeret som kommer opp.
3. Skriv konto-nummeret i text boxen som viser **Enter your account number**
4. Trykk på **Login** *Eller bruk knappen ved siden til og gå til dashboard, hvis du allerede har logget in*

Du skal nå se dashboard siden, hvis du skal laste opp filer, må du ha enkrypsjon nøkkelen til kontoen din
1. Last ned nøkkelen: **partyrock.key** ved og trykke på **Download** knappen.
2. Det anbefales at du sletter nøkkelen fra serveren etter du har lastet den ned, trykk på **Delete** knappen.
3. Nå kan du velge din enkrypsjon nøkkel ved og trykke på den nederste **Velg fil** knappen, og velge **partyrock.key** filen som du nylig lastet ned.
4. Du er nå klar til og laste opp filer, Trykk på den øverste **Velg fil** knappen, og velg en fil du vil laste opp.
5. Trykk på **Last opp** knappen.

### Hvordan det fungerer
#### Innlogging
Innlogging systemet er basert på et konto nummer system, som bruker en modul til og lage et tilfeldig konto nummer på lengden av 10, som er lagret på mongoDB databasen, og er lagret som en cookie når du logger inn, og slettes etter 1 uke for å forhindre at noen kan få tak i konto nummeret ditt.
#### Fil-opplasting
Fil-opplasting systemet bruker fil hashing til og verifisere at filen du lastet opp ikke blir endret etter opplasting, for eksempel til og hindre korrupsjon, filen blir delt opp i 32MB chunks, dette gjør det mulig og sjekke filer som er over 2GB i størrelse (2GB er limit i javascript), og det reduserer hvor mye RAM som blir brukt opp til og sjekke filen, fordi den deles opp og sjekker hver del og ikke hele filen på en gang, etter filen har blit sjekket, blir den sendt til serveren, og serveren sjekker filen igjen og verifiserer at filen som er lastet op matcher filen som serveren har fått, og deretter blir filen enkryptert med en enkrypsjon nøkkel som kun brukeren har tilgang til.
#### Fil-nedlasting
Når brukeren velger og laste ned en fil, blir enkrypsjons nøkkelen sendt til serveren fra localStorage i en request, som serveren bruker til og dekryptere filen, og deretter sende den tilbake til brukeren sin nettleser, serveren lagrer ikke den dekrypterte filen eller enkrypsjons nøkkelen.