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

Fil hashing funksjonen git et problem med sjekking av fil størrelse, jeg brukte Github Copilot til å fikse det ved å reset fil pointeren.<br>
JSON Response funksjonen i javascript var laget av GitHub Copilot for mesteparten.

## Dokumentasjon
N/A
