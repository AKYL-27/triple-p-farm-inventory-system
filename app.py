import io
from flask import Flask, render_template, request, jsonify, send_file, send_from_directory, session, redirect, url_for, flash
from werkzeug.security import check_password_hash
from pymongo import MongoClient
from bson import ObjectId
from dotenv import load_dotenv, find_dotenv
from datetime import datetime
from pathlib import Path
import os
from werkzeug.security import generate_password_hash
import qrcode
import base64
from io import BytesIO



# Load environment variables
env_path = find_dotenv()
load_dotenv(dotenv_path=env_path, override=True)

# Debug environment values
print("DEBUG - DB_NAME:", os.getenv("DB_NAME"))
print("DEBUG - MONGO_URI:", os.getenv("MONGO_URI"))

# Flask app config
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

# MongoDB setup
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")
SUPPLIES_COLLECTION = os.getenv("SUPPLIES_COLLECTION")
EQUIPMENT_COLLECTION = os.getenv("EQUIPMENT_COLLECTION")
FARMERS_COLLECTION = os.getenv("FARMERS_COLLECTION")
BORROW_HISTORY_COLLECTION = os.getenv("BORROW_HISTORY_COLLECTION")
USERS_COLLECTION = os.getenv("USERS_COLLECTION", "users")
SUPPLY_TRANSACTIONS_COLLECTION = os.getenv("SUPPLY_TRANSACTIONS_COLLECTION")
EQUIPMENT_TRANSACTIONS_COLLECTION = os.getenv("EQUIPMENT_TRANSACTIONS_COLLECTION")

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
supplies_collection = db[SUPPLIES_COLLECTION]
equipment_collection = db[EQUIPMENT_COLLECTION]
farmers_collection = db[FARMERS_COLLECTION]
borrow_history_collection = db[BORROW_HISTORY_COLLECTION]
users_collection = db[USERS_COLLECTION]
supply_transactions_collection = db[SUPPLY_TRANSACTIONS_COLLECTION]
equipment_transactions_collection = db[EQUIPMENT_TRANSACTIONS_COLLECTION]

print("Connected to DB:", DB_NAME)


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = users_collection.find_one({"username": username})

        if user and check_password_hash(user["password"], password):
            session["user_id"] = str(user["_id"])
            session["username"] = user["username"]
            session["role"] = user.get("role", "user")
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/user/register", methods=["GET", "POST"])
def register_user():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not all([username, password]):
            return jsonify({"message": "Username and password required"}), 400

        if users_collection.find_one({"username": username}):
            return jsonify({"message": "Username already exists"}), 400

        hashed_password = generate_password_hash(password)

        user = {
            "username": username,
            "password": hashed_password,
            "role": "admin",  # or "user" for roles
            "dateCreated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        result = users_collection.insert_one(user)
        return jsonify({"message": "User created", "id": str(result.inserted_id)}), 201

    return render_template("signup.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session or session.get("role") != "admin":
            flash("Admin login required.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/dashboard")
@admin_required
def dashboard():
    return render_template("index.html", username=session.get("username"))

@app.route('/api/admin/login', methods=['POST'])
def api_admin_login():
    data = request.get_json()

    if not data:
        return jsonify({"message": "Invalid request, expected JSON"}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    user = users_collection.find_one({"username": username, "role": "admin"})
    if not user:
        return jsonify({"message": "Admin not found"}), 404

    if not check_password_hash(user["password"], password):
        return jsonify({"message": "Invalid credentials"}), 401

    return jsonify({
        "message": "Admin login successful",
        "role": "admin",
        "user": {
            "id": str(user["_id"]),
            "username": user["username"]
        }
    }), 200


# ---------------------
# Frontend routes
# ---------------------

@app.route('/customer/inquiries')
def inquiries():
    return render_template('customer/customer.html')

@app.route('/inventory/supplies', methods=['GET'])
def supplies():
    return render_template('inventory/supplies.html')

@app.route('/inventory/equipment')
def equipment():
    return render_template('inventory/equipments.html')

@app.route('/borrow/tools')
def tools():
    return render_template('borrow/borrowed.html')

@app.route('/register', methods=['POST'])
def register_farmer():
    # Try parsing JSON body (from Android app)
    data = request.get_json()

    if not data:
        return jsonify({"message": "Invalid request, expected JSON"}), 400

    name = data.get("fullname")   # match Android field
    contact = data.get("phone")
    password = data.get("password")
    address = data.get("address")
    crop = data.get("cropType")

    # Optional extra field
    birthday = data.get("birthday")  

    if not all([name, contact, password, address, crop]):
        return jsonify({"message": "All fields are required"}), 400

    # Hash password
    hashed_password = generate_password_hash(password)

    farmer = {
        "name": name,
        "contact": contact,
        "password": hashed_password,
        "location": address,    # address field
        "crop": crop,
        "birthday": birthday,   # optional
        "dateRegistered": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "pending"    # default
    }

    result = farmers_collection.insert_one(farmer)

    return jsonify({
        "message": "Please wait for approval",
        "id": str(result.inserted_id)
    }), 201

@app.route('/api/farmers/approved', methods=['GET'])
def get_approved_farmers():
    farmers = list(farmers_collection.find({"status": "approved"}))
    for f in farmers:
        f["_id"] = str(f["_id"])
        del f["password"]  # never expose passwords
    return jsonify(farmers)


@app.route('/api/farmers/pending', methods=['GET'])
def get_pending_farmers():
    farmers = list(farmers_collection.find({"status": "pending"}))
    for f in farmers:
        f["_id"] = str(f["_id"])
        del f["password"]  # Don't expose password
    return jsonify(farmers)

@app.route('/api/farmers/<farmer_id>/approve', methods=['PUT'])
def approve_farmer(farmer_id):
    result = farmers_collection.update_one(
        {"_id": ObjectId(farmer_id)},
        {"$set": {"status": "approved"}}
    )
    if result.modified_count:
        return jsonify({"message": "Farmer approved"}), 200
    return jsonify({"message": "Farmer not found"}), 404


@app.route('/api/farmers/<farmer_id>/decline', methods=['PUT'])
def decline_farmer(farmer_id):
    result = farmers_collection.update_one(
        {"_id": ObjectId(farmer_id)},
        {"$set": {"status": "declined"}}
    )
    if result.modified_count:
        return jsonify({"message": "Farmer declined"}), 200
    return jsonify({"message": "Farmer not found"}), 404

@app.route('/login', methods=['POST'])
def login_farmer():
    data = request.get_json()

    if not data:
        return jsonify({"message": "Invalid request, expected JSON"}), 400

    phone = data.get("phone")
    password = data.get("password")

    if not phone or not password:
        return jsonify({"message": "Phone and password are required"}), 400

    # Find farmer by phone
    farmer = farmers_collection.find_one({"contact": phone})
    if not farmer:
        return jsonify({"message": "Farmer not found"}), 404

    # Check password
    if not check_password_hash(farmer["password"], password):
        return jsonify({"message": "Invalid credentials"}), 401

    return jsonify({
        "message": "Login successful",
        "farmer": {
            "id": str(farmer["_id"]),
            "name": farmer["name"],
            "phone": farmer["contact"],
            "location": farmer["location"],
            "crop": farmer["crop"],
            "birthday": farmer.get("birthday"),
            "status": farmer.get("status")
        }
    }), 200

@app.route('/farmers/approved')
def approved_farmers():
    return render_template('farmers/approved.html')

@app.route('/farmers/pending')
def pending_farmers():
    return render_template('farmers/approval.html')

@app.route('/charts/reports')
def reports():
    return render_template('charts/reports.html')

# ---------------------
# API routes
# ---------------------

@app.route('/reset-password', methods=['POST'])
def reset_farmer_password():
    """
    Reset password for a farmer based on phone number.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request, expected JSON"}), 400

    phone = data.get("phone")
    new_password = data.get("newPassword")

    if not phone or not new_password:
        return jsonify({"error": "Phone and newPassword are required"}), 400

    # Find farmer
    farmer = farmers_collection.find_one({"contact": phone})
    if not farmer:
        return jsonify({"error": "Farmer not found"}), 404

    # Update password (hashed)
    hashed_password = generate_password_hash(new_password)
    farmers_collection.update_one(
        {"_id": farmer["_id"]},
        {"$set": {"password": hashed_password}}
    )

    return jsonify({"message": f"Password reset successful for {farmer['name']}"}), 200


@app.route('/api/admin/reset-password', methods=['POST'])
def reset_admin_password():
    """
    Reset password for an admin based on username.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request, expected JSON"}), 400

    username = data.get("username")
    new_password = data.get("newPassword")

    if not username or not new_password:
        return jsonify({"error": "Username and newPassword are required"}), 400

    # Find admin
    user = users_collection.find_one({"username": username, "role": "admin"})
    if not user:
        return jsonify({"error": "Admin not found"}), 404

    # Update password (hashed)
    hashed_password = generate_password_hash(new_password)
    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"password": hashed_password}}
    )

    return jsonify({"message": f"Password reset successful for admin {username}"}), 200
    
# Register farmer
@app.route('/api/farmers', methods=['GET'])
def get_farmers():
    farmers = list(farmers_collection.find())
    for f in farmers:
        f["_id"] = str(f["_id"])
        del f["password"]  # Don't expose password hashes
    return jsonify(farmers)

#  Create supply
@app.route('/inventory/supplies', methods=['POST'])
def insert_supply():
    try:
        data = request.get_json()
        supply = {
            "name": data.get("name"),
            "quantity": int(data.get("quantity", 0)),
            "unitPrice": float(data.get("unitPrice", 0)),
            "expirationDate": data.get("expirationDate"),
            "dateAdded": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "transactionType": "IN"  # Always IN for adding
        }

        # Insert the supply
        result = supplies_collection.insert_one(supply)
        supply_id = str(result.inserted_id)

        # Insert transaction record for the new supply
        transaction_record = {
            "supplyId": supply_id,
            "supplyName": supply["name"],
            "transactionType": "IN",
            "transactionAmount": supply["quantity"],
            "dateAdded": supply["dateAdded"],
            "previousQuantity": 0,
            "newQuantity": supply["quantity"],
            "unitPrice": supply["unitPrice"],
            "expirationDate": supply.get("expirationDate")
        }
        supply_transactions_collection.insert_one(transaction_record)

        return jsonify({"message": "Supply added", "id": supply_id}), 201

    except Exception as e:
        return jsonify({"message": str(e)}), 500



@app.route('/api/supply/<supply_id>', methods=['GET'])
def get_supply(supply_id):
    try:
        supply = supplies_collection.find_one({"_id": ObjectId(supply_id)})
        if not supply:
            return jsonify({"message": "Supply not found"}), 404

        # Convert ObjectId to string
        supply["_id"] = str(supply["_id"])
        return jsonify(supply)
    except Exception as e:
        return jsonify({"message": str(e)}), 500

# Read supplies
@app.route('/api/supplies', methods=['GET'])
def get_supplies():
    try:
        supplies = list(supplies_collection.find())
        for s in supplies:
            s["_id"] = str(s["_id"])  # Convert ObjectId to string
        return jsonify(supplies)
    except Exception as e:
        return jsonify({"message": str(e)}), 500

# Update supply
@app.route('/api/supplies/<supply_id>', methods=['PUT'])
def update_supply(supply_id):
    try:
        data = request.get_json()
        
        # Get current supply data
        current_supply = supplies_collection.find_one({"_id": ObjectId(supply_id)})
        if not current_supply:
            return jsonify({"message": "Supply not found"}), 404
        
        # Start with the base quantity from the form
        new_quantity = int(data.get("quantity"))
        
        # Determine transaction type based on what's provided
        transaction_type = None
        transaction_amount = 0  # NEW: Track actual transaction amount
        
        # Handle IN quantity (add to current quantity)
        if data.get("inQuantity"):
            in_qty = int(data["inQuantity"])
            if in_qty > 0:
                new_quantity = current_supply["quantity"] + in_qty
                transaction_type = "IN"
                transaction_amount = in_qty  # NEW: Store the IN amount
        
        # Handle OUT quantity (subtract from current quantity)
        if data.get("outQuantity"):
            out_qty = int(data["outQuantity"])
            if out_qty > 0:
                new_quantity = max(0, current_supply["quantity"] - out_qty)
                transaction_type = "OUT"
                transaction_amount = out_qty  # NEW: Store the OUT amount
        
        # If both IN and OUT are provided, calculate net change
        if data.get("inQuantity") and data.get("outQuantity"):
            in_qty = int(data["inQuantity"])
            out_qty = int(data["outQuantity"])
            net_change = in_qty - out_qty
            new_quantity = max(0, current_supply["quantity"] + net_change)
            transaction_type = "IN" if net_change > 0 else "OUT" if net_change < 0 else "ADJUSTED"
            transaction_amount = abs(net_change)  # NEW: Store absolute net change
        
        # If no IN/OUT quantity provided, use the quantity from the form directly
        if not data.get("inQuantity") and not data.get("outQuantity"):
            transaction_type = "UPDATED"
            transaction_amount = 0  # NEW: No transaction amount for updates

        # ===== ADD THIS SECTION - Save transaction to history =====
        if transaction_amount > 0 and transaction_type in ["IN", "OUT"]:
            transaction_record = {
                "supplyId": supply_id,
                "supplyName": current_supply["name"],
                "transactionType": transaction_type,
                "transactionAmount": transaction_amount,
                "dateAdded": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "previousQuantity": current_supply["quantity"],
                "newQuantity": new_quantity,
                "unitPrice": float(data.get("unitPrice", current_supply.get("unitPrice", 0))),
                "expirationDate": data.get("expirationDate", current_supply.get("expirationDate"))
            }
            supply_transactions_collection.insert_one(transaction_record)
        # ===== END OF NEW SECTION =====
        
        update_data = {
            "name": data.get("name"),
            "quantity": new_quantity,
            "unitPrice": float(data.get("unitPrice", 0)),
            "expirationDate": data.get("expirationDate"),
            "transactionType": transaction_type,
            "transactionAmount": transaction_amount,  # NEW FIELD
            "dateUpdated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        result = supplies_collection.update_one(
            {"_id": ObjectId(supply_id)}, 
            {"$set": update_data}
        )
        
        if result.modified_count:
            return jsonify({"message": "Supply updated successfully"}), 200
        else:
            return jsonify({"message": "No changes made"}), 200
            
    except Exception as e:
        return jsonify({"message": str(e)}), 500
        
# Add these new endpoints to your Flask backend

@app.route('/api/supply/<supply_id>/stock', methods=['PUT'])
def update_supply_stock(supply_id):
    try:
        data = request.get_json()
        quantity = int(data.get("quantity", 0))
        transaction_type = data.get("transactionType")  # "stock-in" or "stock-out"

        if quantity <= 0:
            return jsonify({"message": "Quantity must be positive"}), 400

        if transaction_type not in ["stock-in", "stock-out"]:
            return jsonify({"message": "Invalid transaction type"}), 400

        # Get current supply
        current_supply = supplies_collection.find_one({"_id": ObjectId(supply_id)})
        if not current_supply:
            return jsonify({"message": "Supply not found"}), 404

        current_quantity = current_supply.get("quantity", 0)

        # Calculate new quantity
        if transaction_type == "stock-in":
            new_quantity = current_quantity + quantity
            transaction_code = "IN"
            message = f"Successfully added {quantity} units. New quantity: {new_quantity}"
        else:  # stock-out
            if quantity > current_quantity:
                return jsonify({"message": "Insufficient stock"}), 400
            new_quantity = current_quantity - quantity
            transaction_code = "OUT"
            message = f"Successfully removed {quantity} units. New quantity: {new_quantity}"

        # ===== SAVE TRANSACTION (SAME AS update_supply) =====
        transaction_record = {
            "supplyId": supply_id,
            "supplyName": current_supply.get("name"),
            "transactionType": transaction_code,
            "transactionAmount": quantity,
            "previousQuantity": current_quantity,
            "newQuantity": new_quantity,
            "unitPrice": float(current_supply.get("unitPrice", 0)),
            "expirationDate": current_supply.get("expirationDate"),
            "dateAdded": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        supply_transactions_collection.insert_one(transaction_record)
        # ===== END TRANSACTION SAVE =====

        # Update the supply
        update_data = {
            "quantity": new_quantity,
            "transactionType": transaction_code,
            "transactionAmount": quantity,
            "dateUpdated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        result = supplies_collection.update_one(
            {"_id": ObjectId(supply_id)},
            {"$set": update_data}
        )

        if result.modified_count:
            updated_supply = supplies_collection.find_one({"_id": ObjectId(supply_id)})
            updated_supply["_id"] = str(updated_supply["_id"])

            return jsonify({
                "message": message,
                "supply": updated_supply
            }), 200

        return jsonify({"message": "No changes made"}), 200

    except Exception as e:
        return jsonify({"message": str(e)}), 500




@app.route('/api/equipment/<equipment_id>/stock', methods=['PUT'])
def update_equipment_stock(equipment_id):
    try:
        data = request.get_json()
        quantity = int(data.get("quantity", 0))
        transaction_type = data.get("transactionType")  # "stock-in" or "stock-out"

        if quantity <= 0:
            return jsonify({"message": "Quantity must be positive"}), 400

        if transaction_type not in ["stock-in", "stock-out"]:
            return jsonify({"message": "Invalid transaction type"}), 400

        # Get current equipment
        current_equipment = equipment_collection.find_one({"_id": ObjectId(equipment_id)})
        if not current_equipment:
            return jsonify({"message": "Equipment not found"}), 404

        current_quantity = current_equipment.get("quantity", 0)

        # Calculate new quantity
        if transaction_type == "stock-in":
            new_quantity = current_quantity + quantity
            message = f"Successfully added {quantity} units. New quantity: {new_quantity}"
        else:  # stock-out
            if quantity > current_quantity:
                return jsonify({"message": "Insufficient stock"}), 400
            new_quantity = current_quantity - quantity
            message = f"Successfully removed {quantity} units. New quantity: {new_quantity}"

        # Update the equipment
        update_data = {
            "quantity": new_quantity,
            "transactionType": transaction_type.upper().replace("-", "_"),
            "dateUpdated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        # Update lastUsed if stock-out
        if transaction_type == "stock-out":
            update_data["lastUsed"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # Optionally increment borrow count
            equipment_collection.update_one(
                {"_id": ObjectId(equipment_id)},
                {"$inc": {"totalBorrowCount": 1}}
            )

        result = equipment_collection.update_one(
            {"_id": ObjectId(equipment_id)},
            {"$set": update_data}
        )

        if result.modified_count or transaction_type == "stock-out":
            # Get updated equipment
            updated_equipment = equipment_collection.find_one({"_id": ObjectId(equipment_id)})
            updated_equipment["_id"] = str(updated_equipment["_id"])
            
            return jsonify({
                "message": message,
                "equipment": updated_equipment
            }), 200
        else:
            return jsonify({"message": "No changes made"}), 200

    except Exception as e:
        return jsonify({"message": str(e)}), 500



# Generate QR for a specific supply by ID
@app.route('/api/supply/<supply_id>/qrcode', methods=['GET'])
def generate_supply_qr(supply_id):
    try:
        # ✅ Encode the item with a prefix so the scanner knows what it is
        qr_data = f"item_id:{supply_id}"
        
        # Generate QR
        qr_img = qrcode.make(qr_data)
        img_io = io.BytesIO()
        qr_img.save(img_io, 'PNG')
        img_io.seek(0)
        
        # Return image directly
        return send_file(img_io, mimetype='image/png')
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# Delete supply
@app.route('/api/supplies/<supply_id>', methods=['DELETE'])
def delete_supply(supply_id):
    try:
        result = supplies_collection.delete_one({"_id": ObjectId(supply_id)})
        if result.deleted_count == 1:
            return jsonify({"message": "Supply deleted"}), 200
        else:
            return jsonify({"message": "Supply not found"}), 404
    except Exception as e:
        return jsonify({"message": str(e)}), 500
    
@app.route('/inventory/statistics', methods=['GET'])
def inventory_statistics():
    pipeline = [
        {
            "$group": {
                "_id": {
                    "month": {"$month": {"$toDate": "$dateAdded"}},
                    "year": {"$year": {"$toDate": "$dateAdded"}},
                    "type": "$transactionType"
                },
                "total": {"$sum": "$quantity"}
            }
        },
        {"$sort": {"_id.year": 1, "_id.month": 1}}
    ]

    results = list(supplies_collection.aggregate(pipeline))

    # Initialize dictionary for all months
    stats = {m: {"IN": 0, "OUT": 0} for m in range(1, 13)}

    for r in results:
        month = r["_id"]["month"]
        t_type = r["_id"]["type"]
        stats[month][t_type] = r["total"]

    return jsonify(stats)

# New endpoint to get supply transaction history
@app.route('/api/supplies/transactions', methods=['GET'])
def get_supply_transactions():
    try:
        transactions = list(supply_transactions_collection.find())
        
        # Convert ObjectId fields to string
        for t in transactions:
            t["_id"] = str(t["_id"])
            t["supplyId"] = str(t["supplyId"])
        
        return jsonify(transactions), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 500
    
#Create Equipment
@app.route('/inventory/equipment', methods=['POST'])
def insert_equipment():
    data = request.get_json()
    equipment_name = data.get("name")
    added_quantity = int(data.get("quantity"))
    unit = data.get("unit")  # New field
    date_added = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # --- Insert equipment ---
    equipment = {
        "name": equipment_name,
        "quantity": added_quantity,
        "unit": unit,
        "dateAdded": date_added,
        "transactionType": "IN",  # Indicates equipment was added
        "lastUsed": None,
        "totalBorrowCount": 0
    }

    result = equipment_collection.insert_one(equipment)
    equipment_id = str(result.inserted_id)

    # --- Generate QR code ---
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr_data = f"equipment_id:{equipment_id}"
    qr.add_data(qr_data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

    # Update equipment with QR code
    equipment_collection.update_one(
        {"_id": ObjectId(equipment_id)},
        {"$set": {"qrCode": qr_base64}}
    )

    # --- Insert transaction record with correct previous/new quantities ---
    transaction = {
        "equipmentId": equipment_id,               # string ID
        "equipmentName": equipment_name,
        "transactionType": "IN",
        "transactionAmount": added_quantity,
        "dateAdded": date_added,
        "previousQuantity": 0,                     # new equipment, so previous stock = 0
        "newQuantity": added_quantity,             # after addition
        "notes": "New equipment added"
    }
    equipment_transactions_collection.insert_one(transaction)

    return jsonify({
        "message": "Equipment added",
        "id": equipment_id,
        "qrCode": qr_base64
    })


@app.route('/api/equipment/<equipment_id>', methods=['GET'])
def get_tool(equipment_id):
    try:
        equipment = equipment_collection.find_one({"_id": ObjectId(equipment_id)})
        if not equipment:
            return jsonify({"message": "Equipment not found"}), 404

        # Convert ObjectId to string
        equipment["_id"] = str(equipment["_id"])
        return jsonify(equipment)
    except Exception as e:
        return jsonify({"message": str(e)}), 500

# Read equipment
@app.route('/api/equipment', methods=['GET'])
def get_equipment():
    equipment = list(equipment_collection.find())
    for e in equipment:
        e["_id"] = str(e["_id"])
        e["lastUsed"] = e.get("lastUsed")
        e["totalBorrowCount"] = e.get("totalBorrowCount", 0)
    return jsonify(equipment)


@app.route('/api/equipment/<equipment_id>', methods=['PUT'])
def update_equipment(equipment_id):
    try:
        data = request.get_json()
        
        # Get current equipment data
        current_equipment = equipment_collection.find_one({"_id": ObjectId(equipment_id)})
        if not current_equipment:
            return jsonify({"message": "Equipment not found"}), 404
        
        # Determine transaction type based on what's provided
        transaction_type = "ADMIN_UPDATE"
        new_quantity = current_equipment["quantity"]  # Start with current quantity
        transaction_amount = 0
        
        # Check if IN or OUT quantities are provided
        has_in = data.get("inQuantity") and str(data.get("inQuantity")).strip() != ""
        has_out = data.get("outQuantity") and str(data.get("outQuantity")).strip() != ""
        
        # Handle IN quantity (add to current quantity)
        if has_in:
            in_qty = int(data["inQuantity"])
            if in_qty > 0:
                new_quantity = current_equipment["quantity"] + in_qty
                transaction_type = "IN"
                transaction_amount = in_qty
        
        # Handle OUT quantity (subtract from current quantity)
        if has_out:
            out_qty = int(data["outQuantity"])
            if out_qty > 0:
                new_quantity = max(0, current_equipment["quantity"] - out_qty)
                transaction_type = "OUT"
                transaction_amount = out_qty
        
        # If both IN and OUT are provided, calculate net change
        if has_in and has_out:
            in_qty = int(data["inQuantity"])
            out_qty = int(data["outQuantity"])
            net_change = in_qty - out_qty
            new_quantity = max(0, current_equipment["quantity"] + net_change)
            transaction_type = "IN" if net_change > 0 else "OUT" if net_change < 0 else "ADJUSTED"
            transaction_amount = abs(net_change)
        
        # If neither IN nor OUT provided, use the quantity from the form (manual edit)
        if not has_in and not has_out:
            new_quantity = int(data.get("quantity", current_equipment["quantity"]))

        # Save transaction to history
        if transaction_amount > 0:
            transaction_record = {
                "equipmentId": equipment_id,
                "equipmentName": current_equipment["name"],
                "transactionType": transaction_type,
                "transactionAmount": transaction_amount,
                "dateAdded": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "previousQuantity": current_equipment["quantity"],
                "newQuantity": new_quantity
            }
            equipment_transactions_collection.insert_one(transaction_record)

        # Prepare update data
        update_data = {
            "name": data.get("name", current_equipment["name"]),
            "quantity": new_quantity,
            "unit": data.get("unit", current_equipment.get("unit")),  # <-- NEW
            "transactionType": transaction_type,
            "transactionAmount": transaction_amount,
            "dateUpdated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Update lastUsed and totalBorrowCount only when OUT quantity is used
        if has_out and data.get("outQuantity"):
            out_qty = int(data["outQuantity"])
            if out_qty > 0:
                update_data["lastUsed"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                update_data["totalBorrowCount"] = current_equipment.get("totalBorrowCount", 0) + out_qty
        
        equipment_collection.update_one(
            {"_id": ObjectId(equipment_id)}, 
            {"$set": update_data}
        )
        
        return jsonify({"message": "Equipment updated successfully"}), 200
        
    except Exception as e:
        return jsonify({"message": str(e)}), 500


@app.route('/api/equipment/migrate-transactions', methods=['POST'])
def migrate_equipment_transactions():
    """One-time migration to create transaction history from existing borrow counts"""
    try:
        equipment_list = list(equipment_collection.find())
        migrated_count = 0
        
        for equipment in equipment_list:
            total_borrows = equipment.get("totalBorrowCount", 0)
            
            # If equipment has borrows but no transaction history
            if total_borrows > 0:
                # Check if we already have transactions for this equipment
                existing = equipment_transactions_collection.find_one({
                    "equipmentId": str(equipment["_id"]),
                    "transactionType": "OUT"
                })
                
                if not existing:
                    # Create a transaction record for the total borrows
                    last_used = equipment.get("lastUsed", equipment.get("dateAdded", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                    
                    transaction_record = {
                        "equipmentId": str(equipment["_id"]),
                        "equipmentName": equipment["name"],
                        "transactionType": "OUT",
                        "transactionAmount": total_borrows,
                        "dateAdded": last_used,  # Use lastUsed date
                        "previousQuantity": equipment["quantity"] + total_borrows,
                        "newQuantity": equipment["quantity"]
                    }
                    equipment_transactions_collection.insert_one(transaction_record)
                    migrated_count += 1
            
            # Also create an IN transaction for initial stock
            initial_stock = equipment.get("quantity", 0) + equipment.get("totalBorrowCount", 0)
            if initial_stock > 0:
                date_added = equipment.get("dateAdded", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                
                # Check if IN transaction exists
                existing_in = equipment_transactions_collection.find_one({
                    "equipmentId": str(equipment["_id"]),
                    "transactionType": "IN"
                })
                
                if not existing_in:
                    transaction_record = {
                        "equipmentId": str(equipment["_id"]),
                        "equipmentName": equipment["name"],
                        "transactionType": "IN",
                        "transactionAmount": initial_stock,
                        "dateAdded": date_added,
                        "previousQuantity": 0,
                        "newQuantity": initial_stock
                    }
                    equipment_transactions_collection.insert_one(transaction_record)
                    migrated_count += 1
        
        return jsonify({
            "message": f"Migration complete. Created {migrated_count} transaction records.",
            "success": True
        }), 200
        
    except Exception as e:
        return jsonify({"message": str(e), "success": False}), 500

# get transaction history
@app.route('/api/equipment/transactions', methods=['GET'])
def get_equipment_transactions():
    transactions = list(equipment_transactions_collection.find())
    for t in transactions:
        t["_id"] = str(t["_id"])
    return jsonify(transactions)

# Get borrow history for a specific farmer
@app.route('/api/borrow/history/farmer/<farmer_name>', methods=['GET'])
def get_farmer_borrow_history(farmer_name):
    history = list(borrow_history_collection.find({"borrowerName": farmer_name}))
    for h in history:
        h["_id"] = str(h["_id"])
        if isinstance(h.get("equipmentId"), ObjectId):
            h["equipmentId"] = str(h["equipmentId"])
    return jsonify(history), 200



# Borrow equipment
@app.route('/api/equipment/<equipment_id>/borrow', methods=['POST'])
def borrow_equipment(equipment_id):
    try:
        data = request.get_json()
        print("Borrow request data:", data)

        borrower_name = data.get("borrowerName")
        borrow_qty = data.get("quantity")

        # Validate input
        if not borrower_name:
            return jsonify({"message": "Missing borrowerName"}), 400
        if borrow_qty is None:
            return jsonify({"message": "Missing quantity"}), 400

        try:
            borrow_qty = int(borrow_qty)
        except ValueError:
            return jsonify({"message": "Quantity must be a number"}), 400

        # Fetch equipment
        current_equipment = equipment_collection.find_one({"_id": ObjectId(equipment_id)})
        if not current_equipment:
            return jsonify({"message": f"Equipment with id {equipment_id} not found"}), 404

        # Check stock
        available_qty = current_equipment.get("quantity", 0)
        if available_qty < borrow_qty:
            return jsonify({
                "message": "Not enough stock",
                "requested": borrow_qty,
                "available": available_qty
            }), 400

        # Update quantity and usage stats
        equipment_collection.update_one(
            {"_id": ObjectId(equipment_id)},
            {
                "$set": {
                    "quantity": available_qty - borrow_qty,
                    "lastUsed": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                },
                "$inc": {"totalBorrowCount": borrow_qty}
            }
        )

        # Record borrow history
        history = {
            "equipmentId": str(current_equipment["_id"]),
            "equipmentName": current_equipment["name"],
            "quantity": borrow_qty,
            "borrowerName": borrower_name,
            "dateBorrowed": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "dateReturned": None,
            "status": "PENDING"
        }
        inserted = borrow_history_collection.insert_one(history)
        history["_id"] = str(inserted.inserted_id)

        return jsonify({
            "message": "Equipment borrowed successfully",
            "remaining": available_qty - borrow_qty,
            "borrowedItem": history
        }), 200

    except Exception as e:
        # Log the exception for debugging
        print("Error in borrow_equipment:", str(e))
        return jsonify({"message": f"Internal server error: {str(e)}"}), 500
    
@app.route('/api/borrow-requests', methods=['GET'])
def get_borrow_requests():
    # Sort PENDING requests by dateBorrowed (newest first)
    requests = list(
        borrow_history_collection
        .find({"status": "PENDING"})
        .sort("dateBorrowed", -1)
    )

    for r in requests:
        r["_id"] = str(r["_id"])
        r["borrowId"] = r["_id"]  # alias for frontend QR

        if isinstance(r.get("equipmentId"), ObjectId):
            r["equipmentId"] = str(r["equipmentId"])

    return jsonify(requests), 200




@app.route('/api/borrow-requests/<request_id>/accept', methods=['POST'])
def accept_borrow_request(request_id):
    try:
        # Find the borrow request
        borrow_record = borrow_history_collection.find_one({"_id": ObjectId(request_id)})
        if not borrow_record:
            return jsonify({"message": "Borrow request not found"}), 404

        # Generate QR code for returning (FULL URL)
        qr_data = f"http://{request.host}/api/borrow/{str(request_id)}/return"
        qr_img = qrcode.make(qr_data)
        buffer = BytesIO()
        qr_img.save(buffer, format="PNG")
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

        # Update borrow history
        borrow_history_collection.update_one(
            {"_id": ObjectId(request_id)},
            {"$set": {
                "status": "ACCEPTED",
                "qrCode": qr_code_base64
            }}
        )

        return jsonify({"message": "Request accepted with QR code"})
    
    except Exception as e:
        return jsonify({"message": str(e)}), 500


@app.route('/api/borrow-requests/<request_id>/decline', methods=['POST'])
def decline_borrow_request(request_id):
    borrow_history_collection.update_one(
        {"_id": ObjectId(request_id)},
        {"$set": {"status": "DECLINED"}}
    )

    updated = borrow_history_collection.find_one({"_id": ObjectId(request_id)})
    updated["_id"] = str(updated["_id"])
    if isinstance(updated.get("equipmentId"), ObjectId):
        updated["equipmentId"] = str(updated["equipmentId"])

    return jsonify({
        "message": "Request declined",
        "borrowId": updated["_id"],  # Still return it for consistency
        "request": updated
    }), 200

@app.route('/api/borrow/<history_id>/return', methods=['PUT'])
def return_equipment(history_id):
    try:
        # Find borrow record by its history _id
        history = borrow_history_collection.find_one({"_id": ObjectId(history_id)})
        if not history:
            return jsonify({"message": "Borrow history not found"}), 404

        # Prevent double return
        if history.get("status") == "RETURNED":
            return jsonify({"message": "This item was already returned"}), 400

        # Restore equipment quantity
        eq_id = history["equipmentId"]
        query = {"_id": ObjectId(eq_id)} if ObjectId.is_valid(eq_id) else {"_id": eq_id}
        equipment_collection.update_one(
            query,
            {"$inc": {"quantity": history["quantity"]}}
        )

        # Mark as returned
        borrow_history_collection.update_one(
            {"_id": ObjectId(history_id)},
            {"$set": {
                "dateReturned": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "RETURNED"
            }}
        )

        return jsonify({"message": "Equipment returned successfully"}), 200

    except Exception as e:
        return jsonify({"message": str(e)}), 500

# Get borrow history list
@app.route('/api/borrow/history', methods=['GET'])
def get_borrow_history():
    # Sort by dateBorrowed descending (-1)
    history = list(
        borrow_history_collection.find().sort("dateBorrowed", -1)
    )

    for h in history:
        h["_id"] = str(h["_id"])
        if isinstance(h.get("equipmentId"), ObjectId):
            h["equipmentId"] = str(h["equipmentId"])

        # Generate QR code only if missing
        if not h.get("qrCode"):
            qr_data = f"http://{request.host}/api/borrow/{h['_id']}/return"
            qr_img = qrcode.make(qr_data)
            buffer = BytesIO()
            qr_img.save(buffer, format="PNG")
            qr_code_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

            borrow_history_collection.update_one(
                {"_id": ObjectId(h["_id"])},
                {"$set": {"qrCode": qr_code_base64}}
            )
            h["qrCode"] = qr_code_base64

    return jsonify(history), 200



@app.route('/api/equipment/<equipment_id>', methods=['DELETE'])
def delete_equipment(equipment_id):
    try:
        result = equipment_collection.delete_one({"_id": ObjectId(equipment_id)})
        if result.deleted_count == 1:
            return jsonify({"message": "Equipment deleted"}), 200
        else:
            return jsonify({"message": "Equipment not found"}), 404
    except Exception as e:
        return jsonify({"message": str(e)}), 500
    
@app.route('/inventory/low-stock-equipment', methods=['GET'])
def low_stock_equipment():
    threshold = int(request.args.get("threshold", 5))  # e.g., < 5 items
    equipment = list(equipment_collection.find({"quantity": {"$lt": threshold}}))

    for e in equipment:
        e["_id"] = str(e["_id"])
    return jsonify(equipment)

@app.route('/inventory/low-stock', methods=['GET'])
def low_stock():
    threshold = int(request.args.get("threshold", 10))  # default < 10
    supplies = list(supplies_collection.find({"quantity": {"$lt": threshold}}))
    
    # Convert ObjectId to string for JSON
    for s in supplies:
        s["_id"] = str(s["_id"])
    return jsonify(supplies)


    
# ---------------------
# Chatfuel stock lookup
# ---------------------

# --- List all available supplies (stock > 0)
@app.route('/api/products', methods=['GET'])
def list_supplies():
    try:
        # Get all supplies with name + quantity
        supplies = list(supplies_collection.find({}, {"name": 1, "quantity": 1}))

        available_supplies = [
            {"name": s["name"], "stock": s.get("quantity", 0)}
            for s in supplies if s.get("quantity", 0) > 0
        ]

        if not available_supplies:
            return jsonify({
                "status": "ok",
                "message": "No supplies are currently available.",
                "products": []
            }), 200

        # Build a readable text list for chatbot
        product_lines = [f"• {s['name']} — {s['stock']} in stock" for s in available_supplies]
        product_list = "\n".join(product_lines)

        return jsonify({
            "status": "ok",
            "message": f"📦 Available supplies:\n\n{product_list}",
            "products": available_supplies
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"⚠️ Error: {str(e)}",
            "products": []
        }), 200

# --- Check stock for a specific supply name
@app.route('/api/products/check', methods=['GET'])
def check_supply():
    try:
        # Get product name from query parameter
        product_name = request.args.get("name")
        if not product_name:
            return jsonify({
                "status": "error",
                "message": "Please provide a product name."
            }), 400
        
        # Find supply by name (case-insensitive) - include unitPrice in projection
        supply = supplies_collection.find_one(
            {"name": {"$regex": f"^{product_name}$", "$options": "i"}}, 
            {"name": 1, "quantity": 1, "unitPrice": 1}
        )
        
        if not supply:
            return jsonify({
                "status": "ok",
                "message": f"Sorry, '{product_name}' is not found in the inventory."
            }), 200
        
        qty = supply.get("quantity", 0)
        unit_price = supply.get("unitPrice", 0)
        
        # Format unit price to 2 decimal places
        price_str = f"₱{float(unit_price):.2f}"
        
        if qty > 0:
            return jsonify({
                "status": "ok",
                "message": f"Yes, {supply['name']} is available. Stock: {qty}. Unit Price: {price_str}."
            }), 200
        else:
            return jsonify({
                "status": "ok",
                "message": f"Sorry, {supply['name']} is currently out of stock. Unit Price: {price_str}."
            }), 200
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/products/validate', methods=['GET'])
def validate_product():
    product_name = request.args.get("name")
    requested_qty = request.args.get("qty", type=int)

    if not product_name:
        return jsonify({"status": "ERROR", "message": "Please provide a product name."}), 400

    # Find supply case-insensitive
    supply = supplies_collection.find_one(
        {"name": {"$regex": f"^{product_name}$", "$options": "i"}}
    )

    if not supply:
        return jsonify({
            "status": "NOT_FOUND",
            "message": f"Sorry, '{product_name}' is not found in the inventory."
        }), 200

    available_qty = supply.get("quantity", 0)
    unit_price = supply.get("unitPrice", 0)
    price_str = f"₱{float(unit_price):.2f}"

    # If quantity is not provided yet, just check availability
    if requested_qty is None:
        if available_qty > 0:
            return jsonify({
                "status": "AVAILABLE",
                "message": f"{supply['name']} is available. Stock: {available_qty}. Unit Price: {price_str}."
            }), 200
        else:
            return jsonify({
                "status": "OUT_OF_STOCK",
                "message": f"Sorry, {supply['name']} is out of stock. Unit Price: {price_str}."
            }), 200

    # Quantity validation
    if requested_qty > available_qty:
        return jsonify({
            "status": "INSUFFICIENT_STOCK",
            "message": f"Sorry, only {available_qty} in stock. Please enter a lower quantity."
        }), 200

    if requested_qty <= available_qty:
        total_price = requested_qty * unit_price
        total_price_str = f"₱{total_price:.2f}"

        return jsonify({
            "status": "VALID",
            "message": (
                f"✅ {supply['name']} is available.\n"
                f"Requested Quantity: {requested_qty}\n"
                f"Unit Price: {price_str}\n"
                f"Total Price: {total_price_str}\n"            
            )
        }), 200

# ---------------------
if __name__ == "__main__":
    app.run(debug=True)
