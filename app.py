import base64
from flask import Flask, jsonify, render_template, request, make_response, send_file, redirect # Alle flask moduler som trengs.
from werkzeug.utils import secure_filename # Sikkerhets modul som sjekker filnavn til og ungå angrep som exploiter serveren ved et farlig filnavn, werkzeug.utils kan også brukes til enkrypsjon av filer hvis nødvendig, men jeg har ikke lagt til dette.
import secrets # Modul som genererer random tall, og er litt mer randomisert enn den vanlige random modulen.
import pymongo as mongo # Modul som lar serveren koble till MongoDB databasen som handler bruker informasjon.
import re # Modul som gjør det lettere og parse dokumenter, brukes til og finne informasjon i databasen.
import os # Modul som gir serveren tilgang til operativ system funksjoner, brukes til lagring av filer og lage nye mapper.
import hashlib
from cryptography.fernet import Fernet
from flask_cors import CORS # Del av flask, lar serveren kommunisere med andre servere, den brukes til kommunikasjon med frontend.
from datetime import timedelta # Modul som gjør det lettere og sette en expiration med cookies, ved bruk av dager i stedet for sekunder.

app = Flask(__name__)
CORS(app, supports_credentials=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/button-click', methods=['GET'])
def button_click():
    generatednumber = secrets.randbelow(9999999999) + 1
    mongo_client = mongo.MongoClient('mongodb://localhost:27017/')
    db = mongo_client['meow']
    collection = db['woof']
    doc = {"number": generatednumber}
    try:
        x = collection.insert_one(doc)
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

@app.route('/login-existing', methods=['POST'])
def check_existing_number():
    data = request.get_json()
    print("Data: ", data)
    try:
        number = int(data.get('accountNumber'))
    except ValueError:
        return jsonify({"error": "Input is not an integer"}), 400

    print("Entered number: ", number)
    
    mongo_client = mongo.MongoClient('mongodb://localhost:27017/')
    db = mongo_client['meow']
    collection = db['woof']
    
    existing_doc = collection.find_one({"number": number})
    print("Existing doc: ", existing_doc)
    parsed_doc = str(existing_doc)
    
    try:
        number_only = re.findall(r'\d+', parsed_doc)
        if number_only:
            number_only = int(number_only[-1])
            print("Number only: ", number_only)
            resp = make_response("Hello, world!")
            resp.set_cookie('account', str(number_only), max_age=timedelta(days=7)) # Cookie vil vare i 7 dager, jeg valgte og legge til dette for privacy og sikkerhet av brukeren sin konto, Kilde: https://verdantfox.com/blog/cookies-with-the-flask-web-framework#cookie-expirations
            print("Cookie debug: ", resp)
            print("Cookie set: ", request.cookies.get('account'))
            
            return resp
        else:
            print("No number found in the document")
            raise ValueError("No number found in the document")
    except ValueError as e:
        print(e)
        return jsonify({"message": "Number does not exist in the database"})

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    # Her skal vi sjekke om brukeren sin cookie matcher en bruker i databasen, hvis den matcher så skal vi vise dashboard.html med denne brukeren sin konto innhold
    account_number = request.cookies.get('account')
    if account_number and account_number.isdigit() and len(account_number) <= 11:
        account_number = int(account_number)
        print("Account number: ", account_number)
    else:
        return jsonify({"error": "Invalid account number"}), 400
    mongo_client = mongo.MongoClient('mongodb://localhost:27017/')
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
    
@app.route('/upload-file', methods=['POST', 'GET'])
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
    filehash = request.form.get('sha1hash')
    keyfile = request.form.get('keyFile')
    file_content = file.read()
    serversidehash = hashlib.sha1(file_content).hexdigest()
    file.seek(0)  # Reset the file pointer to the start
    print("Client hash: ", filehash)
    print("Server hash: ", serversidehash)
    if file.filename == '':
        print("No file was returned")
        return jsonify({"error": "No selected file"}), 400
    if filehash != serversidehash:
        print("Hashes do not match")
        return jsonify({"error": "Hashes do not match"}), 400
    if file and filehash == serversidehash:
        print("Hashes match, file encryption starting")
        filename = secure_filename(file.filename)
        print("Filename: ", filename)
        if keyfile:
            print("Keyfile provided: ", keyfile)
            key = Fernet(keyfile)
        else:
            print("No key file provided")
            return jsonify({"error": "No key file provided"}), 400
        print("Key: ", key)
        encrypted_file = key.encrypt(file_content)
        with open(f'./data/{account_number}/{filename}', 'wb') as f:
            f.write(encrypted_file)
        print("File saved with encryption")
        return jsonify({"message": "File uploaded successfully"}), 200

@app.route('/get-files', methods=['GET'])
def get_files():
    account_number = request.cookies.get('account')
    print("Account number for get files: ", account_number)
    if not os.path.exists(f'./data/{account_number}'):
        os.makedirs(f'./data/{account_number}')
    try:
        files = os.listdir(f'./data/{account_number}')
        print("Files: ", files)
        file_info = [{'name': f, 'size': str(round(os.path.getsize(f'./data/{account_number}/{f}') / 1000000, 2)) + " MB"} for f in files]
        print("File info: ", file_info)
    except FileNotFoundError:
        print("No files found")
        return jsonify({"message": "No files found"}), 404
    return jsonify(file_info)

@app.route('/download-file/<filename>', methods=['POST'])
def download_file(filename):
    account_number = request.cookies.get('account')
    print("Account number: ", account_number)
    filepath = f'./data/{account_number}/{filename}'
    print("Filepath: ", filepath)
    sha1 = hashlib.sha1()
    sha1.update(open(filepath, 'rb').read())
    print("File hash: ", sha1.hexdigest())

    key = request.form.get('keyFile')
    fernet = Fernet(key)

    try:
        with open(filepath, 'rb') as file:
            encrypted_data = file.read()
            decrypted_data = fernet.decrypt(encrypted_data)
    except FileNotFoundError:
        print(f"File {filepath} not found")
        return jsonify({"message": f"File {filepath} not found"}), 404
    except Exception as e:
        print("Decryption failed:", str(e))
        return jsonify({"message": "Decryption failed"}), 500

    response = make_response(decrypted_data)
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return response

@app.route('/delete-file/<filename>', methods=['GET'])
def delete_file(filename):
    account_number = request.cookies.get('account')
    print("Account number to be used for file deletion: ", account_number)
    os.remove(f'./data/{account_number}/{filename}')
    return redirect('/dashboard')


if __name__ == '__main__':
    app.run(debug=True)
