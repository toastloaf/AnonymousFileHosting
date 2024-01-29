import base64
from flask import Flask, jsonify, render_template, request, make_response, send_file, redirect # Alle flask moduler som trengs.
from werkzeug.utils import secure_filename # Sikkerhets modul som sjekker filnavn til og ungå angrep som exploiter serveren ved et farlig filnavn, werkzeug.utils kan også brukes til enkrypsjon av filer hvis nødvendig, men jeg har ikke lagt til dette.
import secrets # Modul som genererer random tall, og er litt mer randomisert enn den vanlige random modulen.
import pymongo as mongo # Modul som lar serveren koble till MongoDB databasen som handler bruker informasjon.
import re # Modul som gjør det lettere og parse dokumenter, brukes til og finne informasjon i databasen.
import os # Modul som gir serveren tilgang til operativ system funksjoner, brukes til lagring av filer og lage nye mapper.
import hashlib # Fil hashing modul til server-side fil sjekking, brukes til og sjekke om filen er endret under opplasting.
from cryptography.fernet import Fernet # Fil enkryptering modul, brukes til og enkryptere filer som blir lastet opp til serveren og dekryptere filer som blir lastet ned fra serveren.
from flask_cors import CORS # Del av flask, lar serveren kommunisere med andre servere, den brukes til kommunikasjon med frontend.
from datetime import timedelta # Modul som gjør det lettere og sette en expiration med cookies, ved bruk av dager i stedet for sekunder.

app = Flask(__name__) # Lager en instanse av flask, og kaller den app.
CORS(app, supports_credentials=True) # Denne linjen lar serveren kommunisere med andre servere, og lar serveren motta cookies fra andre servere (frontend).

@app.route('/') # Denne linjen er en route, den lar serveren vite hvilken side som skal vises når brukeren går til en spesifikk URL.
def index():
    return render_template('index.html') # Denne linjen lar serveren vite hvilken HTML fil som skal vises når brukeren går til en spesifikk URL.

@app.route('/button-click', methods=['GET'])
def button_click():
    generatednumber = secrets.randbelow(9999999999) + 1 # Denne linjen genererer et random tall mellom 1 og 9999999999, mer random enn random.randint(1, 9999999999).
    mongo_client = mongo.MongoClient('mongodb://localhost:27017/') # Denne linjen kobler til MongoDB databasen.
    db = mongo_client['meow'] # MongoDB bruker et system av flere databaser og collections, denne linjen lar serveren vite hvilken database som skal brukes.
    collection = db['woof'] # Collection som skal brukes i databasen.
    doc = {"number": generatednumber} # Dokumentet som skal legges til i databasen.
    try:
        x = collection.insert_one(doc) # Denne linjen legger til dokumentet i databasen.
        print(x.inserted_id)
        # Nå skal vi lage enkyrpteringsnøkkel for brukeren, og lagre den i folderen til brukeren.
        key = Fernet.generate_key()
        f = Fernet(key)
        if not os.path.exists(f'./data/{generatednumber}'):
            os.makedirs(f'./data/{generatednumber}')
        with open(f'./data/{generatednumber}/partyrock.key', 'wb') as key_file:
            key_file.write(key)
        print("Key file created for user ", generatednumber)
    except Exception as e:
        print("An error occurred:", e)
        return jsonify({"error": str(e)}), 500
    return jsonify(generatednumber)

@app.route('/login-existing', methods=['POST']) # Merk at denne linjen har methods=['POST'], dette betyr at denne routen kan bruke POST requests.
def check_existing_number():
    data = request.get_json()
    print("Data: ", data)
    try:
        number = int(data.get('accountNumber'))
    except ValueError:
        return jsonify({"error": "Input is not an integer"}), 400 # Brukeren har skrevet inn noe som ikke er et tall, kan være på uhell eller et angrep som prøver og exploite serveren.

    print("Entered number: ", number)
    
    mongo_client = mongo.MongoClient('mongodb://localhost:27017/') # Koble til databasen igjen.
    db = mongo_client['meow']
    collection = db['woof']
    
    existing_doc = collection.find_one({"number": number}) # Denne linjen sjekker om brukeren sitt nummer eksisterer i databasen.
    print("Existing doc: ", existing_doc)
    parsed_doc = str(existing_doc) # Parser dokumentet, gjør det mulig og finne informasjon i dokumentet.
    
    try:
        number_only = re.findall(r'\d+', parsed_doc)
        if number_only:
            number_only = int(number_only[-1])
            print("Number only: ", number_only)
            resp = make_response("Hello, world!") # Denne linjen lager en respons som skal sendes til brukeren.
            resp.set_cookie('account', str(number_only), max_age=timedelta(days=7)) # Cookie vil vare i 7 dager, jeg valgte og legge til dette for privacy og sikkerhet av brukeren sin konto, Kilde: https://verdantfox.com/blog/cookies-with-the-flask-web-framework#cookie-expirations
            
            return resp
        else:
            print("No number found in the document")
            raise ValueError("No number found in the document")
    except ValueError as e:
        print(e)
        return jsonify({"message": "Number does not exist in the database"}) # Kontoen eksisterer ikke i databasen.

@app.route('/dashboard', methods=['GET', 'POST']) # Denne linjen har methods=['GET', 'POST'], dette betyr at denne routen kan bruke GET og POST requests.
def dashboard():
    # Her skal vi sjekke om brukeren sin cookie matcher en bruker i databasen, hvis den matcher så skal vi vise dashboard.html med denne brukeren sin konto innhold
    account_number = request.cookies.get('account')
    if account_number and account_number.isdigit() and len(account_number) <= 11:
        account_number = int(account_number)
        print("Account number: ", account_number)
    else:
        return jsonify({"error": "Invalid account number"}), 400
    mongo_client = mongo.MongoClient('mongodb://localhost:27017/') # Koble til databasen igjen.
    db = mongo_client['meow']
    collection = db['woof']
    existing_doc = collection.find_one({"number": int(account_number)})
    print("Existing doc: ", existing_doc)
    parsed_doc = str(existing_doc)
    try:
        number_only = re.findall(r'\d+', parsed_doc)
        if number_only:
            number_only = int(number_only[-1])
            print("Number only: ", number_only)
            return render_template('dashboard.html', accountNumber=number_only)
        else:
            raise ValueError("No number found in the document")
    except ValueError as e:
        print(e)
        return jsonify({"message": "Number does not exist in the database"})
    
@app.route('/upload-file', methods=['POST', 'GET']) # Denne routen er til og laste opp filer til serveren.
def upload_file():
    account_number = request.cookies.get('account')
    if account_number and account_number.isdigit() and len(account_number) <= 11:
        account_number = int(account_number)
        print("Account number: ", account_number)
    else:
        return jsonify({"error": "Invalid account number"}), 400
    print("Account number for upload: ", int(account_number))
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    file = request.files['file']
    filehash = request.form.get('sha1hash') # Denne linjen henter fil hashen som brukeren har generert på sin nettleser.
    keyfile = request.form.get('keyFile') # Denne linjen henter enkrypteringsnøkkelen som brukeren har sent fra nettleseren.
    file_content = file.read()
    serversidehash = hashlib.sha1(file_content).hexdigest() # Serveren genererer en hash av filen som brukeren har lastet opp.
    file.seek(0) # Resetter fil pointeren til 0, fordi den har blitt flyttet til slutten av filen etter at vi genererte en hash av filen.
    print("Client hash: ", filehash)
    print("Server hash: ", serversidehash)
    if file.filename == '':
        print("No file was returned")
        return jsonify({"error": "No selected file"}), 400 # Brukeren har ikke valgt en fil.
    if filehash != serversidehash:
        print("Hashes do not match")
        return jsonify({"error": "Hashes do not match"}), 400 # Hashene matcher ikke, filen er endret under opplasting.
    if file and filehash == serversidehash:
        print("Hashes match, file encryption starting") # Hashene matcher, filen er identisk til den som brukeren har lastet opp, som betyr at opplastingen var vellykket.
        filename = secure_filename(file.filename) # Denne linjen sjekker filnavnet til brukeren for og unngå angrep som exploiter serveren ved et farlig filnavn.
        print("Filename: ", filename)
        if keyfile:
            print("Keyfile provided")
            key = Fernet(keyfile) # Definerer enkrypteringsnøkkelen som brukeren har sent fra nettleseren.
        else:
            print("No key file provided")
            return jsonify({"error": "No key file provided"}), 400 # Brukeren har ikke sent enkrypteringsnøkkelen sin.
        encrypted_file = key.encrypt(file_content) # Denne linjen enkrypterer filen som brukeren har lastet opp ved bruk av enkrypteringsnøkkelen som brukeren har sent fra nettleseren.
        with open(f'./data/{account_number}/{filename}', 'wb') as f:
            f.write(encrypted_file) # Denne linjen lagrer den enkrypterte filen i brukeren sin mappe.
        print("File saved with encryption")
        return jsonify({"message": "File uploaded successfully"}), 200

@app.route('/get-files', methods=['GET']) # Denne routen er til og hente filer fra serveren.
def get_files():
    account_number = request.cookies.get('account')
    if account_number and account_number.isdigit() and len(account_number) <= 11: # Det kan hende at du har merket denne linjen i flere routes, dette er for og sjekke om brukeren sin cookie matcher en bruker i databasen, plus extra sjekker for og unngå angrep.
        account_number = int(account_number)
        print("Account number: ", account_number)
    else:
        return jsonify({"error": "Invalid account number"}), 400
    print("Account number for get files: ", account_number)
    if not os.path.exists(f'./data/{account_number}'):
        os.makedirs(f'./data/{account_number}') # Hvis brukeren ikke har en mappe i data mappen, så lager vi en mappe til brukeren.
    try:
        files = os.listdir(f'./data/{account_number}') # Denne linjen henter alle filer i brukeren sin mappe.
        print("Files: ", files)
        file_info = [{'name': f, 'size': str(round(os.path.getsize(f'./data/{account_number}/{f}') / 1000000, 2)) + " MB"} for f in files] # Denne linjen henter filnavn og filstørrelse for hver fil i brukeren sin mappe, bruker en mattefunksjon for og dele filstørrelsen og gjøre den om til megabytes.
        print("File info: ", file_info)
    except FileNotFoundError:
        print("No files found")
        return jsonify({"message": "No files found"}), 404 # Brukeren har ingen filer i sin mappe.
    return jsonify(file_info)

@app.route('/download-file/<filename>', methods=['POST']) # Denne routen er til og laste ned filer fra serveren.
def download_file(filename):
    account_number = request.cookies.get('account')
    if account_number and account_number.isdigit() and len(account_number) <= 11:
        account_number = int(account_number)
        print("Account number: ", account_number)
    else:
        return jsonify({"error": "Invalid account number"}), 400
    print("Account number: ", account_number)
    filepath = f'./data/{account_number}/{filename}'
    print("Filepath: ", filepath)
    sha1 = hashlib.sha1()
    sha1.update(open(filepath, 'rb').read()) # Denne linjen genererer en hash av filen som brukeren vil laste ned.
    print("File hash: ", sha1.hexdigest())

    if filename == 'partyrock.key':
        print("Key file requested")
        return send_file(filepath, as_attachment=True) # Denne linjen lar brukeren laste ned enkrypteringsnøkkelen sin, fordi den trenger ikke og være enkryptert.

    key = request.form.get('keyFile') # Denne linjen henter enkrypteringsnøkkelen som brukeren har sent fra nettleseren.
    fernet = Fernet(key)

    try:
        with open(filepath, 'rb') as file:
            encrypted_data = file.read()
            decrypted_data = fernet.decrypt(encrypted_data)
    except FileNotFoundError:
        print(f"File {filepath} not found")
        return jsonify({"message": f"File {filepath} not found"}), 404 # Filen eksisterer ikke i brukeren sin mappe.
    except Exception as e:
        print("Decryption failed:", str(e))
        return jsonify({"message": "Decryption failed"}), 500 # Dekrypteringen feilet, brukeren har mest sannsynlig sendt feil enkrypteringsnøkkel.
    
    response = make_response(decrypted_data)
    response.headers['Content-Disposition'] = f'attachment; filename={filename}' # Denne linjen lager en respons som skal sendes til brukeren.
    return response # Sender responsen til brukeren.

@app.route('/delete-file/<filename>', methods=['GET']) # Denne routen er til og slette filer fra serveren.
def delete_file(filename):
    account_number = request.cookies.get('account')
    if account_number and account_number.isdigit() and len(account_number) <= 11:
        account_number = int(account_number)
        print("Account number: ", account_number)
    else:
        return jsonify({"error": "Invalid account number"}), 400
    print("Account number to be used for file deletion: ", account_number)
    os.remove(f'./data/{account_number}/{filename}') # Denne linjen sletter filen fra brukeren sin mappe.
    return redirect('/dashboard')


if __name__ == '__main__':
    app.run(debug=True) # Denne linjen starter serveren.
