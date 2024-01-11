from flask import Flask, jsonify, render_template, request, make_response, send_file
from werkzeug.utils import secure_filename
import secrets
import pymongo as mongo
import re
import os
from flask_cors import CORS

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
    except Exception as e:
        print("An error occurred:", e)
        return jsonify({"error": str(e)}), 500
    return jsonify(generatednumber)

@app.route('/login-existing', methods=['POST'])
def check_existing_number():
    data = request.get_json()
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
            resp.set_cookie('account', str(number_only))
            print("Cookie debug: ", resp)
            print("Cookie set: ", request.cookies.get('account'))
            
            return resp # Return the response object
        else:
            raise ValueError("No number found in the document")
    except ValueError as e:
        print(e)
        return jsonify({"message": "Number does not exist in the database"})

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    # Her skal vi sjekke om brukeren sin cookie matcher en bruker i databasen, hvis den matcher så skal vi vise dashboard.html med denne brukeren sin konto innhold
    account_number = request.cookies.get('account')
    print("Account number: ", account_number)
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
    
@app.route('/upload', methods=['POST', 'GET'])
def upload_file():
    account_number = request.cookies.get('account')
    print("Account number: ", account_number)
    if 'file' not in request.files:
        return 'No file part in the request', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(f'./data/{account_number}', filename))
        return 'File uploaded!', 200

@app.route('/get-files', methods=['GET'])
def get_files():
    account_number = request.cookies.get('account')
    if not os.path.exists(f'./data/{account_number}'):
        os.makedirs(f'./data/{account_number}')
    try:
        files = os.listdir(f'./data/{account_number}')
        file_info = [{'name': f, 'size': os.path.getsize(f'./data/{f}')} for f in files]
    except FileNotFoundError:
        print("FUCK")
        return jsonify({"message": "No files found"}), 404
    return jsonify(file_info)

@app.route('/download-file/<filename>', methods=['GET'])
def download_file(filename):
    account_number = request.cookies.get('account')
    print("Account number: ", account_number)
    return send_file(f'./data/{account_number}/{filename}', as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
