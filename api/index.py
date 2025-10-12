
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from pymongo import MongoClient
from flask_socketio import SocketIO, emit, join_room
import qrcode
import base64
from io import BytesIO
import uuid
from datetime import datetime, timedelta, timezone
import random
import smtplib
from email.mime.text import MIMEText
from bson import ObjectId
import os

app = Flask(__name__)
CORS(app)
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Change in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
jwt = JWTManager(app)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading", 
    transports=["websocket"]
)

# -------------------------------
# MongoDB Setup
# -------------------------------
client = MongoClient("mongodb+srv://infoshreeharshshivpuje_db_user:cBIyxliUzqDl1LpM@cluster0.ccjkejl.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["flask_auth_db"]
users_collection = db["users"]
items_collection = db["items"]
messages_collection = db["messages"]
found_items_collection = db["found_items"]
lost_items_collection = db["lost_items"]

# -------------------------------
# Helper function to generate QR code
# -------------------------------
def generate_user_qr(user_custom_id):
    qr_data = f"{user_custom_id}"
    qr_img = qrcode.make(qr_data)
    buffered = BytesIO()
    qr_img.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
    return qr_base64

# -------------------------------
# Initialize default privacy settings for existing users
# -------------------------------
def initialize_privacy_settings():
    users_collection.update_many(
        {"privacy": {"$exists": False}},
        {"$set": {
            "privacy": {
                "qr_code_visibility": True,
                "profile_visibility": "only_known_users",
                "two_factor_auth": False
            }
        }}
    )
    print("Initialized privacy settings for all users")

# Call this function when the server starts
initialize_privacy_settings()

# -------------------------------
# User Signup
# -------------------------------
@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        full_name = data.get('full_name')

        if not email or not password or not full_name:
            return jsonify({"msg": "Full name, email, and password are required"}), 400

        # Check if email is verified via OTP
        if email not in otp_storage or not otp_storage[email].get('verified', False):
            return jsonify({"msg": "Email not verified. Please complete OTP verification first."}), 400

        # Check if user already exists
        if users_collection.find_one({"email": email}):
            return jsonify({"msg": "User already exists"}), 400

        # Validate password strength
        if len(password) < 6:
            return jsonify({"msg": "Password must be at least 6 characters long"}), 400

        password_hash = generate_password_hash(password)
        custom_id = f"FMB_USER_{uuid.uuid4().hex[:8]}"

        user_doc = {
            "email": email,
            "full_name": full_name,
            "password_hash": password_hash,
            "phone": data.get("phone"),
            "alternate_email": data.get("alternate_email"),
            "student_id": data.get("student_id"),
            "department": data.get("department"),
            "organization": data.get("organization"),
            "address": data.get("address"),
            "profile_image": data.get("profile_image"),
            "custom_id": custom_id,
            "email_verified": True,  # Mark email as verified since OTP was completed
            "privacy": {
                "qr_code_visibility": True,
                "profile_visibility": "only_known_users",
                "two_factor_auth": False
            },
            "notifications": {
                "push_notifications": True,
                "found_item_alerts": True,
                "message_notifications": True,
                "scan_notifications": False,
                "sound_vibration": True
            },
            "preferences": {
                "theme": "system_default",
                "language": "english",
                "auto_login": True
            },
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }

        inserted = users_collection.insert_one(user_doc)
        qr_base64 = generate_user_qr(custom_id)

        users_collection.update_one(
            {"_id": inserted.inserted_id},
            {"$set": {"qr_code": qr_base64}}
        )

        # Clean up OTP storage after successful signup
        if email in otp_storage:
            del otp_storage[email]

        access_token = create_access_token(identity=email)
        
        return jsonify({
            "msg": "Signup successful",
            "token": access_token,
            "qr_code": qr_base64,
            "custom_id": custom_id,
            "user": {
                "email": email,
                "full_name": full_name,
                "custom_id": custom_id,
                "department": data.get("department", ""),
                "email_verified": True
            }
        }), 201

    except Exception as e:
        print(f"Error during signup: {e}")
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500
    
# -------------------------------
# OTP Storage
# -------------------------------
otp_storage = {}  # Temporary storage for OTPs

# -------------------------------
# Email configuration
# -------------------------------
SMTP_CONFIG = {
    'server': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
    'port': int(os.getenv('SMTP_PORT', 587)),
    'username': os.getenv('SMTP_USERNAME', 'testacc200flask@gmail.com'),
    'password': os.getenv('SMTP_PASSWORD', 'igfntlfnskzcazkj')  # Use App Password for Gmail
}

def send_otp_email(email, otp):
    """Send OTP to user's email"""
    try:
        subject = "Your Find My Belongings Verification Code"
        body = f"""
Hello,

Your verification code for Find My Belongings is: {otp}

This code will expire in 10 minutes.

If you didn't request this code, please ignore this email.

Best regards,
Find My Belongings Team
"""
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = SMTP_CONFIG['username']
        msg['To'] = email

        # STARTTLS connection
        with smtplib.SMTP(SMTP_CONFIG['server'], SMTP_CONFIG['port']) as server:
            server.starttls()
            server.login(SMTP_CONFIG['username'], SMTP_CONFIG['password'])
            server.send_message(msg)
        
        return True
    except smtplib.SMTPAuthenticationError as e:
        print(f"SMTP Authentication failed: {e}")
        return False
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# -------------------------------
# Send OTP
# -------------------------------
@app.route('/auth/send-otp', methods=['POST'])
def send_otp():
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({"msg": "Email is required"}), 400

        if users_collection.find_one({"email": email}):
            return jsonify({"msg": "Email already registered"}), 400

        otp = str(random.randint(100000, 999999))
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

        otp_storage[email] = {
            'otp': otp,
            'expires_at': expires_at,
            'attempts': 0
        }

        if send_otp_email(email, otp):
            return jsonify({"msg": "OTP sent successfully", "expires_in": 600}), 200
        else:
            return jsonify({"msg": "Failed to send OTP"}), 500

    except Exception as e:
        print(f"Error sending OTP: {e}")
        return jsonify({"msg": "Internal server error"}), 500

# -------------------------------
# Verify OTP
# -------------------------------
@app.route('/auth/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()
        email = data.get('email')
        otp = data.get('otp')

        if not email or not otp:
            return jsonify({"msg": "Email and OTP are required"}), 400

        if email not in otp_storage:
            return jsonify({"msg": "OTP not found or expired"}), 400

        otp_data = otp_storage[email]

        if datetime.now(timezone.utc) > otp_data['expires_at']:
            del otp_storage[email]
            return jsonify({"msg": "OTP has expired"}), 400

        if otp_data['attempts'] >= 3:
            del otp_storage[email]
            return jsonify({"msg": "Too many failed attempts"}), 400

        if otp_data['otp'] == otp:
            otp_storage[email]['verified'] = True
            return jsonify({"msg": "Email verified successfully", "verified": True}), 200
        else:
            otp_storage[email]['attempts'] += 1
            remaining_attempts = 3 - otp_storage[email]['attempts']
            return jsonify({"msg": f"Invalid OTP. {remaining_attempts} attempts remaining", "verified": False}), 400

    except Exception as e:
        print(f"Error verifying OTP: {e}")
        return jsonify({"msg": "Internal server error"}), 500

# -------------------------------
# Resend OTP
# -------------------------------
@app.route('/auth/resend-otp', methods=['POST'])
def resend_otp():
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({"msg": "Email is required"}), 400

        otp = str(random.randint(100000, 999999))
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

        otp_storage[email] = {
            'otp': otp,
            'expires_at': expires_at,
            'attempts': 0
        }

        if send_otp_email(email, otp):
            return jsonify({"msg": "OTP resent successfully", "expires_in": 600}), 200
        else:
            return jsonify({"msg": "Failed to resend OTP"}), 500

    except Exception as e:
        print(f"Error resending OTP: {e}")
        return jsonify({"msg": "Internal server error"}), 500

# -------------------------------
# User Login
# -------------------------------
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    print("Received login data:", data)

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"msg": "Email and password required"}), 400

    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"msg": "Invalid credentials"}), 401

    if not check_password_hash(user['password_hash'], password):
        return jsonify({"msg": "Invalid credentials"}), 401

    # Update last login time
    users_collection.update_one(
        {"email": email},
        {"$set": {"last_login": datetime.utcnow()}}
    )

    access_token = create_access_token(identity=email)

    qr_base64 = user.get('qr_code', None)
    user_id = user.get('custom_id', None)
    full_name = user.get('full_name', email.split('@')[0])
    department = user.get('department', 'General')
    student_id = user.get('student_id', None)
    phone = user.get('phone', None)
    address = user.get('address', None)
    
    # Get privacy settings
    privacy_settings = user.get('privacy', {})
    qr_code_visibility = privacy_settings.get('qr_code_visibility', True)
    profile_visibility = privacy_settings.get('profile_visibility', 'only_known_users')
    two_factor_auth = privacy_settings.get('two_factor_auth', False)
    
    # Get notification settings
    notification_settings = user.get('notifications', {})
    push_notifications = notification_settings.get('push_notifications', True)
    found_item_alerts = notification_settings.get('found_item_alerts', True)
    message_notifications = notification_settings.get('message_notifications', True)
    scan_notifications = notification_settings.get('scan_notifications', False)
    sound_vibration = notification_settings.get('sound_vibration', True)

    print("User found:", {
        "userId": user_id,
        "full_name": full_name,
        "department": department,
        "student_id": student_id,
        "phone": phone,
        "address": address,
        "qr_code": qr_base64 is not None
    })

    return jsonify({
        "token": access_token,
        "qr_code": qr_base64,
        "userId": user_id,
        "full_name": full_name,
        "department": department,
        "student_id": student_id,
        "phone": phone,
        "address": address,
        "privacy": {
            "qr_code_visibility": qr_code_visibility,
            "profile_visibility": profile_visibility,
            "two_factor_auth": two_factor_auth
        },
        "notifications": {
            "push_notifications": push_notifications,
            "found_item_alerts": found_item_alerts,
            "message_notifications": message_notifications,
            "scan_notifications": scan_notifications,
            "sound_vibration": sound_vibration
        }
    }), 200

@app.route('/google-login', methods=['POST'])
def google_login():
    data = request.get_json()
    print("✅ /google-login endpoint hit!")  # Debug line
    print("Received Google login data:", data)

    email = data.get('email')
    supabase_user_id = data.get('supabase_user_id')
    full_name = data.get('full_name', '')
    profile_picture = data.get('profile_picture', '')

    if not email:
        return jsonify({"msg": "Email is required"}), 400

    # Check if user exists in MongoDB
    user = users_collection.find_one({"email": email})
    
    if user:
        # User exists - update last login and supabase_user_id if needed
        update_data = {
            "last_login": datetime.now(timezone.utc),  # FIXED: changed from utcnow()
            "supabase_user_id": supabase_user_id
        }
        
        # Update profile picture if provided and different
        if profile_picture and user.get('profile_image') != profile_picture:
            update_data["profile_image"] = profile_picture
            
        # Update name if provided and different
# Only set name if it's empty (so we don't overwrite user's chosen name)
        if not user.get('full_name') and full_name:
            update_data["full_name"] = full_name

        users_collection.update_one(
            {"email": email},
            {"$set": update_data}
        )
        
        # Generate JWT token
        access_token = create_access_token(identity=email)
        
        # Return user data similar to normal login
        qr_base64 = user.get('qr_code', None)
        user_id = user.get('custom_id', None)
        full_name = user.get('full_name', full_name)  # Use DB name if available
        department = user.get('department', 'General')
        student_id = user.get('student_id', None)
        phone = user.get('phone', None)
        address = user.get('address', None)
        
        # Get privacy settings
        privacy_settings = user.get('privacy', {})
        qr_code_visibility = privacy_settings.get('qr_code_visibility', True)
        profile_visibility = privacy_settings.get('profile_visibility', 'only_known_users')
        two_factor_auth = privacy_settings.get('two_factor_auth', False)
        
        # Get notification settings
        notification_settings = user.get('notifications', {})
        push_notifications = notification_settings.get('push_notifications', True)
        found_item_alerts = notification_settings.get('found_item_alerts', True)
        message_notifications = notification_settings.get('message_notifications', True)
        scan_notifications = notification_settings.get('scan_notifications', False)
        sound_vibration = notification_settings.get('sound_vibration', True)

        print("Google user found:", {
            "userId": user_id,
            "full_name": full_name,
            "department": department,
            "student_id": student_id,
            "phone": phone,
            "address": address,
            "qr_code": qr_base64 is not None
        })

        return jsonify({
            "token": access_token,
            "qr_code": qr_base64,
            "userId": user_id,
            "full_name": full_name,
            "department": department,
            "student_id": student_id,
            "phone": phone,
            "address": address,
            "privacy": {
                "qr_code_visibility": qr_code_visibility,
                "profile_visibility": profile_visibility,
                "two_factor_auth": two_factor_auth
            },
            "notifications": {
                "push_notifications": push_notifications,
                "found_item_alerts": found_item_alerts,
                "message_notifications": message_notifications,
                "scan_notifications": scan_notifications,
                "sound_vibration": sound_vibration
            },
            "is_new_user": False
        }), 200
    else:
        # New user - create account in MongoDB
        custom_id = f"FMB_USER_{random.randint(10000000, 99999999)}"
        
        # Generate QR code for new user
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(custom_id)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")
        
        buffered = BytesIO()
        qr_img.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode()
        
        new_user = {
            "email": email,
            "full_name": full_name,
            "password_hash": "",  # No password for Google users
            "phone": "",
            "student_id": "",
            "department": "General",
            "organization": "",
            "address": "",
            "profile_image": profile_picture,
            "custom_id": custom_id,
            "email_verified": True,
            "privacy": {
                "qr_code_visibility": True,
                "profile_visibility": "only_known_users",
                "two_factor_auth": False
            },
            "notifications": {
                "push_notifications": True,
                "found_item_alerts": True,
                "message_notifications": True,
                "scan_notifications": False,
                "sound_vibration": True
            },
            "preferences": {
                "theme": "system_default",
                "language": "english",
                "auto_login": True
            },
            "created_at": datetime.now(timezone.utc),  # FIXED
            "updated_at": datetime.now(timezone.utc),  # FIXED
            "qr_code": qr_base64,
            "last_login": datetime.now(timezone.utc),  # FIXED
            "supabase_user_id": supabase_user_id,
            "auth_provider": "google"  # Track auth method
        }
        
        result = users_collection.insert_one(new_user)
        
        # Generate JWT token
        access_token = create_access_token(identity=email)
        
        print("New Google user created:", {
            "userId": custom_id,
            "full_name": full_name,
            "email": email,
            "qr_code": True
        })

        return jsonify({
            "token": access_token,
            "qr_code": qr_base64,
            "userId": custom_id,
            "full_name": full_name,
            "department": "General",
            "student_id": "",
            "phone": "",
            "address": "",
            "privacy": {
                "qr_code_visibility": True,
                "profile_visibility": "only_known_users",
                "two_factor_auth": False
            },
            "notifications": {
                "push_notifications": True,
                "found_item_alerts": True,
                "message_notifications": True,
                "scan_notifications": False,
                "sound_vibration": True
            },
            "is_new_user": True
        }), 201


@app.route('/debug/routes', methods=['GET'])
def debug_routes():
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            'endpoint': rule.endpoint,
            'methods': list(rule.methods),
            'path': str(rule)
        })
    return jsonify({"routes": routes}), 200
# -------------------------------
# Get Item by custom_id - FIXED VERSION
# -------------------------------
@app.route('/get_item', methods=['GET'])
def get_item():
    custom_id = request.args.get('custom_id')
    if not custom_id:
        return jsonify({"msg": "custom_id is required"}), 400

    # Normalize the ID to include prefix if missing
    if not custom_id.startswith("FMB_USER_"):
        custom_id = f"FMB_USER_{custom_id}"

    # Fetch user from DB
    user = users_collection.find_one({"custom_id": custom_id}, {"_id": 0})
    if not user:
        return jsonify({"msg": "User/item not found"}), 404

    # Check QR visibility - FIXED LOGIC
    privacy_settings = user.get("privacy", {})
    qr_code_visibility = privacy_settings.get("qr_code_visibility", True)
    
    print(f"QR Code Visibility for {custom_id}: {qr_code_visibility}")  # Debug log
    
    if not qr_code_visibility:
        return jsonify({
            "msg": "This QR code is private and cannot be scanned",
            "error": "QR_CODE_PRIVATE",
            "status": "private"
        }), 403  # Use 403 Forbidden status

    # QR code is visible, return full user info
    user_info = {
        "ownerName": user.get("full_name", "Unknown"),
        "ownerEmail": user.get("email", "Unknown"),
        "department": user.get("department", "Unknown"),
        "userId": user.get("custom_id"),
        "ownerPhoto": user.get("profile_image"),
        "qr_code": user.get("qr_code"),  # Only returned if visibility is True
        "status": "public"
    }

    return jsonify(user_info), 200

# -------------------------------
# Dashboard
# -------------------------------
@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    current_user_email = get_jwt_identity()
    user = users_collection.find_one({"email": current_user_email}, {"_id": 0, "password_hash": 0})

    if not user:
        return jsonify({"msg": "User not found"}), 404

    lost_items = [
        {"id": "1", "title": "Bag near Library", "description": "Black backpack", "time": "2 hrs ago"},
        {"id": "2", "title": "Wallet", "description": "Brown leather wallet", "time": "Yesterday"},
    ]
    notifications = [
        {"id": "1", "type": "scan", "message": "Someone scanned your QR", "time": "5 min ago"},
    ]

    return jsonify({
        "user": user,
        "lostItems": lost_items,
        "notifications": notifications
    }), 200

# -------------------------------
# Message Endpoints
# -------------------------------
@app.route('/messages/send', methods=['POST'])
@jwt_required()
def send_message():
    data = request.get_json()
    
    sender_email = get_jwt_identity()
    sender = users_collection.find_one({"email": sender_email})
    if not sender:
        return jsonify({"msg": "Sender not found"}), 404

    receiver_id = data.get("receiver_id")
    message_text = data.get("message")
    chat_id = data.get("chat_id")

    if not receiver_id:
        return jsonify({"msg": "receiver_id is required"}), 400
    if not receiver_id.startswith("FMB_USER_"):
        return jsonify({"msg": "Invalid receiver_id format"}), 400
    if not message_text:
        return jsonify({"msg": "message is required"}), 400

    if not chat_id:
        ids = sorted([sender['custom_id'], receiver_id])
        chat_id = f"CHAT_{ids[0]}_{ids[1]}"

    message_doc = {
        "chat_id": chat_id,
        "sender_id": sender["custom_id"],
        "receiver_id": receiver_id,
        "message": message_text,
        "timestamp": datetime.utcnow()
    }

    result = messages_collection.insert_one(message_doc)
    
    socketio.emit('new_message', {
        'chat_id': chat_id,
        'sender_id': sender["custom_id"],
        'receiver_id': receiver_id,
        'message': message_text,
        'timestamp': datetime.utcnow().isoformat()
    }, room=chat_id)

    return jsonify({
        "msg": "Message sent successfully",
        "chat_id": chat_id,
        "message_id": str(result.inserted_id)
    }), 201

@app.route('/messages/<chat_id>', methods=['GET'])
@jwt_required()
def get_messages(chat_id):
    current_user_email = get_jwt_identity()
    current_user = users_collection.find_one({"email": current_user_email})
    if not current_user:
        return jsonify({"msg": "User not found"}), 404

    current_user_id = current_user["custom_id"]

    messages_cursor = messages_collection.find(
        {"chat_id": chat_id},
        {"_id": 0}
    ).sort("timestamp", 1)

    messages = []
    for msg in messages_cursor:
        if "timestamp" in msg:
            ts = msg["timestamp"]
            if isinstance(ts, datetime):
                msg["timestamp"] = ts.isoformat()

        msg["is_sender"] = msg["sender_id"] == current_user_id
        messages.append(msg)

    return jsonify(messages), 200

@app.route('/chats', methods=['GET'])
@jwt_required()
def get_user_chats():
    user_email = get_jwt_identity()
    user = users_collection.find_one({"email": user_email})
    if not user:
        return jsonify({"msg": "User not found"}), 404
        
    user_id = user["custom_id"]

    pipeline = [
        {
            "$match": {
                "$or": [
                    {"sender_id": user_id},
                    {"receiver_id": user_id}
                ]
            }
        },
        {
            "$sort": {"timestamp": -1}
        },
        {
            "$group": {
                "_id": "$chat_id",
                "last_message": {"$first": "$message"},
                "sender_id": {"$first": "$sender_id"},
                "receiver_id": {"$first": "$receiver_id"},
                "timestamp": {"$first": "$timestamp"},
            }
        },
        {
            "$sort": {"timestamp": -1}
        }
    ]
    
    chats = list(messages_collection.aggregate(pipeline))
    
    chat_list = []
    for chat in chats:
        other_user_id = chat["receiver_id"] if chat["sender_id"] == user_id else chat["sender_id"]
        
        other_user = users_collection.find_one(
            {"custom_id": other_user_id}, 
            {"_id": 0, "full_name": 1, "email": 1}
        )
        
        chat_list.append({
            "chat_id": chat["_id"],
            "last_message": chat["last_message"],
            "sender_id": chat["sender_id"],
            "receiver_id": chat["receiver_id"],
            "other_user_name": other_user.get("full_name", "Unknown") if other_user else "Unknown",
            "other_user_email": other_user.get("email", "") if other_user else "",
            "timestamp": chat["timestamp"].isoformat() if isinstance(chat["timestamp"], datetime) else str(chat["timestamp"]),
        })

    return jsonify(chat_list), 200

# -------------------------------
# Found Items Endpoints
# -------------------------------
@app.route('/found_items/report', methods=['POST'])
@jwt_required()
def report_found_item():
    try:
        current_user_email = get_jwt_identity()
        data = request.get_json()
        
        finder = users_collection.find_one({"email": current_user_email})
        if not finder:
            return jsonify({"msg": "Finder not found"}), 404

        required_fields = ['item_name', 'item_category', 'item_description', 'found_location', 'owner_info']
        for field in required_fields:
            if field not in data:
                return jsonify({"msg": f"Missing required field: {field}"}), 400

        owner_id = data['owner_info'].get('owner_id')
        if not owner_id:
            return jsonify({"msg": "Owner ID is required"}), 400

        owner = users_collection.find_one({"custom_id": owner_id})
        if not owner:
            return jsonify({"msg": "Item owner not found"}), 404

        found_item_doc = {
            "report_id": f"FOUND_{uuid.uuid4().hex[:8]}",
            "finder_id": finder["custom_id"],
            "finder_email": finder["email"],
            "finder_name": finder.get("full_name", "Unknown"),
            "finder_department": finder.get("department", "Unknown"),
            "finder_phone": finder.get("phone", ""),
            
            "owner_id": owner_id,
            "owner_email": owner.get("email", ""),
            "owner_name": owner.get("full_name", "Unknown"),
            "owner_department": owner.get("department", "Unknown"),
            "owner_phone": owner.get("phone", ""),
            
            "item_name": data['item_name'],
            "item_category": data['item_category'],
            "item_description": data['item_description'],
            "found_location": data['found_location'],
            "found_date_time": datetime.utcnow(),
            
            "evidence_image": data.get('evidence_image'),
            "status": "reported",
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }

        result = found_items_collection.insert_one(found_item_doc)
        
        socketio.emit('new_found_item_report', {
            'report_id': found_item_doc['report_id'],
            'finder_name': found_item_doc['finder_name'],
            'item_name': found_item_doc['item_name'],
            'found_location': found_item_doc['found_location'],
            'timestamp': datetime.utcnow().isoformat()
        }, room=owner_id)

        return jsonify({
            "msg": "Found item report submitted successfully",
            "report_id": found_item_doc['report_id'],
            "status": "reported"
        }), 201

    except Exception as e:
        print(f"Error reporting found item: {e}")
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500

@app.route('/found_items/my_reports', methods=['GET'])
@jwt_required()
def get_my_found_reports():
    try:
        current_user_email = get_jwt_identity()
        user = users_collection.find_one({"email": current_user_email})
        if not user:
            return jsonify({"msg": "User not found"}), 404

        user_id = user["custom_id"]
        
        reports = list(found_items_collection.find(
            {"finder_id": user_id},
            {"_id": 0, "evidence_image": 0}
        ).sort("created_at", -1))

        for report in reports:
            for key, value in report.items():
                if isinstance(value, datetime):
                    report[key] = value.isoformat()

        return jsonify({"reports": reports}), 200

    except Exception as e:
        print(f"Error fetching found reports: {e}")
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500

@app.route('/found_items/reported_to_me', methods=['GET'])
@jwt_required()
def get_found_items_reported_to_me():
    try:
        current_user_email = get_jwt_identity()
        user = users_collection.find_one({"email": current_user_email})
        if not user:
            return jsonify({"msg": "User not found"}), 404

        user_id = user["custom_id"]
        
        reports = list(found_items_collection.find(
            {"owner_id": user_id},
            {"_id": 0, "evidence_image": 0}
        ).sort("created_at", -1))

        for report in reports:
            for key, value in report.items():
                if isinstance(value, datetime):
                    report[key] = value.isoformat()

        return jsonify({"reports": reports}), 200

    except Exception as e:
        print(f"Error fetching found items reported to me: {e}")
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500

@app.route('/found_items/<report_id>/status', methods=['PUT'])
@jwt_required()
def update_found_item_status(report_id):
    try:
        current_user_email = get_jwt_identity()
        data = request.get_json()
        
        new_status = data.get('status')
        valid_statuses = ['reported', 'contacted', 'returned', 'closed']
        
        if new_status not in valid_statuses:
            return jsonify({"msg": f"Invalid status. Must be one of: {valid_statuses}"}), 400

        report = found_items_collection.find_one({"report_id": report_id})
        if not report:
            return jsonify({"msg": "Report not found"}), 404

        user = users_collection.find_one({"email": current_user_email})
        user_id = user["custom_id"]
        
        if user_id not in [report['finder_id'], report['owner_id']]:
            return jsonify({"msg": "Not authorized to update this report"}), 403

        found_items_collection.update_one(
            {"report_id": report_id},
            {
                "$set": {
                    "status": new_status,
                    "updated_at": datetime.utcnow()
                }
            }
        )

        other_party_id = report['owner_id'] if user_id == report['finder_id'] else report['finder_id']
        socketio.emit('found_item_status_updated', {
            'report_id': report_id,
            'new_status': new_status,
            'updated_by': user_id,
            'timestamp': datetime.utcnow().isoformat()
        }, room=other_party_id)

        return jsonify({
            "msg": f"Status updated to {new_status}",
            "report_id": report_id,
            "new_status": new_status
        }), 200

    except Exception as e:
        print(f"Error updating found item status: {e}")
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500

# -------------------------------
# Settings Endpoints
# -------------------------------
@app.route('/user/profile', methods=['PUT'])
@jwt_required()
def update_user_profile():
    try:
        current_user_email = get_jwt_identity()
        data = request.get_json()
        
        update_data = {}
        if 'full_name' in data:
            update_data['full_name'] = data['full_name']
        if 'phone' in data:
            update_data['phone'] = data['phone']
        if 'student_id' in data:  # Add this
            update_data['student_id'] = data['student_id']
        if 'department' in data:
            update_data['department'] = data['department']
        if 'organization' in data:
            update_data['organization'] = data['organization']
        if 'address' in data:
            update_data['address'] = data['address']
        if 'profile_image' in data:
            update_data['profile_image'] = data['profile_image']
        
        update_data['updated_at'] = datetime.utcnow()
        
        result = users_collection.update_one(
            {"email": current_user_email},
            {"$set": update_data}
        )
        
        if result.modified_count > 0:
            updated_user = users_collection.find_one(
                {"email": current_user_email},
                {"_id": 0, "password_hash": 0}
            )
            return jsonify({
                "msg": "Profile updated successfully",
                "user": updated_user
            }), 200
        else:
            return jsonify({"msg": "No changes made to profile"}), 200
            
    except Exception as e:
        print(f"Error updating profile: {e}")
        return jsonify({"msg": "Internal server error"}), 500

@app.route('/user/change-password', methods=['PUT'])
@jwt_required()
def change_password():
    try:
        current_user_email = get_jwt_identity()
        data = request.get_json()
        
        old_password = data.get('old_password')
        new_password = data.get('new_password')
        
        if not old_password or not new_password:
            return jsonify({"msg": "Old password and new password are required"}), 400
        
        user = users_collection.find_one({"email": current_user_email})
        if not user:
            return jsonify({"msg": "User not found"}), 404
        
        if not check_password_hash(user['password_hash'], old_password):
            return jsonify({"msg": "Current password is incorrect"}), 400
        
        new_password_hash = generate_password_hash(new_password)
        
        users_collection.update_one(
            {"email": current_user_email},
            {"$set": {"password_hash": new_password_hash, "updated_at": datetime.utcnow()}}
        )
        
        return jsonify({"msg": "Password changed successfully"}), 200
        
    except Exception as e:
        print(f"Error changing password: {e}")
        return jsonify({"msg": "Internal server error"}), 500

@app.route('/user/notifications', methods=['PUT'])
@jwt_required()
def update_notification_preferences():
    try:
        current_user_email = get_jwt_identity()
        data = request.get_json()
        
        update_data = {
            "notifications.push_notifications": data.get('push_notifications', True),
            "notifications.found_item_alerts": data.get('found_item_alerts', True),
            "notifications.message_notifications": data.get('message_notifications', True),
            "notifications.scan_notifications": data.get('scan_notifications', False),
            "notifications.sound_vibration": data.get('sound_vibration', True),
            "updated_at": datetime.utcnow()
        }
        
        users_collection.update_one(
            {"email": current_user_email},
            {"$set": update_data}
        )
        
        return jsonify({"msg": "Notification preferences updated"}), 200
        
    except Exception as e:
        print(f"Error updating notifications: {e}")
        return jsonify({"msg": "Internal server error"}), 500

@app.route('/user/privacy', methods=['PUT'])
@jwt_required()
def update_privacy_settings():
    try:
        current_user_email = get_jwt_identity()
        data = request.get_json()
        
        update_data = {
            "privacy.qr_code_visibility": data.get('qr_code_visibility', True),
            "privacy.profile_visibility": data.get('profile_visibility', 'only_known_users'),
            "privacy.two_factor_auth": data.get('two_factor_auth', False),
            "updated_at": datetime.utcnow()
        }
        
        users_collection.update_one(
            {"email": current_user_email},
            {"$set": update_data}
        )
        
        return jsonify({"msg": "Privacy settings updated"}), 200
        
    except Exception as e:
        print(f"Error updating privacy settings: {e}")
        return jsonify({"msg": "Internal server error"}), 500

@app.route('/user/preferences', methods=['PUT'])
@jwt_required()
def update_app_preferences():
    try:
        current_user_email = get_jwt_identity()
        data = request.get_json()
        
        update_data = {
            "preferences.theme": data.get('theme', 'system_default'),
            "preferences.language": data.get('language', 'english'),
            "preferences.auto_login": data.get('auto_login', True),
            "updated_at": datetime.utcnow()
        }
        
        users_collection.update_one(
            {"email": current_user_email},
            {"$set": update_data}
        )
        
        return jsonify({"msg": "App preferences updated"}), 200
        
    except Exception as e:
        print(f"Error updating app preferences: {e}")
        return jsonify({"msg": "Internal server error"}), 500

@app.route('/user/settings', methods=['GET'])
@jwt_required()
def get_user_settings():
    try:
        current_user_email = get_jwt_identity()
        print(f"🔍 [Backend] Fetching settings for: {current_user_email}")
        
        # FIX: Remove the exclusion of _id and password_hash, or handle projection properly
        user = users_collection.find_one(
            {"email": current_user_email},
            {
                "notifications": 1,
                "privacy": 1,
                "preferences": 1,
                "linked_accounts": 1
                # Remove: "_id": 0, "password_hash": 0 - these cause the projection error
            }
        )
        
        if not user:
            print("❌ [Backend] User not found")
            return jsonify({"msg": "User not found"}), 404
        
        # Get the actual database values
        notifications = user.get('notifications', {})
        privacy = user.get('privacy', {})
        preferences = user.get('preferences', {})
        
        print(f"🔍 [Backend] User found - Privacy: {privacy}")
        print(f"🔍 [Backend] Notifications: {notifications}")
        
        # FIXED: Use actual database values with proper defaults
        settings = {
            "notifications": {
                "push_notifications": notifications.get('push_notifications', True),
                "found_item_alerts": notifications.get('found_item_alerts', True),
                "message_notifications": notifications.get('message_notifications', True),
                "scan_notifications": notifications.get('scan_notifications', False),
                "sound_vibration": notifications.get('sound_vibration', True)
            },
            "privacy": {
                "qr_code_visibility": privacy.get('qr_code_visibility', True),
                "profile_visibility": privacy.get('profile_visibility', 'only_known_users'),
                "two_factor_auth": privacy.get('two_factor_auth', False)
            },
            "preferences": {
                "theme": preferences.get('theme', 'system_default'),
                "language": preferences.get('language', 'english'),
                "auto_login": preferences.get('auto_login', True)
            },
            "linked_accounts": user.get('linked_accounts', [])
        }
        
        print(f"✅ [Backend] Final settings response: {settings}")
        
        return jsonify(settings), 200
        
    except Exception as e:
        print(f"❌ [Backend] Error in get_user_settings: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500

# Add this debug endpoint to check database values
@app.route('/debug/user/<email>', methods=['GET'])
def debug_user(email):
    try:
        user = users_collection.find_one(
            {"email": email},
            {
                "_id": 0,
                "email": 1,
                "privacy": 1,
                "notifications": 1
            }
        )
        
        if not user:
            return jsonify({"msg": "User not found"}), 404
            
        return jsonify({
            "msg": "User debug info",
            "user": user
        }), 200
        
    except Exception as e:
        return jsonify({"msg": f"Error: {e}"}), 500
    
@app.route('/user/account', methods=['DELETE'])    
@jwt_required()
def delete_user_account():
    try:
        current_user_email = get_jwt_identity()
        
        user = users_collection.find_one({"email": current_user_email})
        if not user:
            return jsonify({"msg": "User not found"}), 404
        
        user_id = user['custom_id']
        
        users_collection.delete_one({"email": current_user_email})
        messages_collection.delete_many({
            "$or": [
                {"sender_id": user_id},
                {"receiver_id": user_id}
            ]
        })
        found_items_collection.delete_many({
            "$or": [
                {"finder_id": user_id},
                {"owner_id": user_id}
            ]
        })
        
        return jsonify({"msg": "Account deleted successfully"}), 200
        
    except Exception as e:
        print(f"Error deleting account: {e}")
        return jsonify({"msg": "Internal server error"}), 500

@app.route('/user/export-data', methods=['GET'])
@jwt_required()
def export_user_data():
    try:
        current_user_email = get_jwt_identity()
        
        user = users_collection.find_one({"email": current_user_email})
        if not user:
            return jsonify({"msg": "User not found"}), 404
        
        user_id = user['custom_id']
        
        user_data = {
            "profile": user,
            "messages": list(messages_collection.find({
                "$or": [
                    {"sender_id": user_id},
                    {"receiver_id": user_id}
                ]
            }, {"_id": 0})),
            "found_items_reported": list(found_items_collection.find(
                {"finder_id": user_id}, {"_id": 0}
            )),
            "found_items_about_me": list(found_items_collection.find(
                {"owner_id": user_id}, {"_id": 0}
            ))
        }
        
        return jsonify({
            "msg": "Data export ready",
            "data": user_data,
            "exported_at": datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error exporting user data: {e}")
        return jsonify({"msg": "Internal server error"}), 500

# -------------------------------
# WebSocket Event Handlers
# -------------------------------
@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")

@socketio.on('join_chat')
def handle_join_chat(data):
    try:
        chat_id = data.get('chat_id')
        if chat_id:
            join_room(chat_id)
            print(f"User joined chat room: {chat_id}")
            emit('user_joined', {'chat_id': chat_id, 'message': 'User joined chat'}, room=chat_id)
        else:
            print("No chat_id provided for join_chat")
    except Exception as e:
        print(f"Error in join_chat: {e}")

@socketio.on('leave_chat')
def handle_leave_chat(data):
    chat_id = data.get('chat_id')
    print(f"User left chat room: {chat_id}")

@socketio.on('typing')
def handle_typing(data):
    try:
        chat_id = data.get('chat_id')
        user_id = data.get('user_id')
        is_typing = data.get('is_typing', False)
        
        if chat_id and user_id:
            emit('user_typing', {
                'user_id': user_id,
                'is_typing': is_typing
            }, room=chat_id, include_self=False)
            print(f"User {user_id} typing in {chat_id}: {is_typing}")
        else:
            print("Missing chat_id or user_id in typing event")
    except Exception as e:
        print(f"Error in typing handler: {e}")

@socketio.on('message_read')
def handle_message_read(data):
    try:
        chat_id = data.get('chat_id')
        user_id = data.get('user_id')
        message_id = data.get('message_id')
        
        if chat_id and user_id:
            emit('message_read_update', {
                'user_id': user_id,
                'message_id': message_id,
                'chat_id': chat_id
            }, room=chat_id)
            print(f"User {user_id} read message in {chat_id}")
    except Exception as e:
        print(f"Error in message_read handler: {e}")

@socketio.on('join_user_room')
def handle_join_user_room(data):
    try:
        user_id = data.get('user_id')
        if user_id:
            join_room(user_id)
            print(f"User joined their room: {user_id}")
    except Exception as e:
        print(f"Error in join_user_room: {e}")

# -------------------------------
# Health check endpoint
# -------------------------------
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "Flask Auth API"
    }), 200

# -------------------------------
# Lost Items Endpoints
# -------------------------------
@app.route('/lost_items/report', methods=['POST'])
@jwt_required()
def report_lost_item():
    try:
        current_user_email = get_jwt_identity()
        data = request.get_json()
        
        user = users_collection.find_one({"email": current_user_email})
        if not user:
            return jsonify({"msg": "User not found"}), 404

        # Required fields
        required_fields = ['item_name', 'color_features', 'location', 'circumstances']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"msg": f"Missing required field: {field}"}), 400

        # Generate unique report ID
        report_id = f"LOST_{uuid.uuid4().hex[:8]}"
        
        # Parse date and time
        loss_datetime = None
        if data.get('loss_date_time'):
            try:
                # Parse format: "DD/MM/YYYY HH:MM AM/PM"
                loss_datetime = datetime.strptime(data['loss_date_time'], '%d/%m/%Y %I:%M %p')
            except ValueError:
                return jsonify({"msg": "Invalid date time format. Use DD/MM/YYYY HH:MM AM/PM"}), 400

        lost_item_doc = {
            "report_id": report_id,
            "user_id": user["custom_id"],
            "user_email": user["email"],
            "user_name": user.get("full_name", "Unknown"),
            "user_phone": user.get("phone", ""),
            "user_department": user.get("department", "Unknown"),
            "user_address": user.get("address", ""),
            
            # Item details
            "item_name": data['item_name'],
            "brand_model": data.get('brand_model', ''),
            "color_features": data['color_features'],
            "serial_number": data.get('serial_number', ''),
            "approximate_value": data.get('approximate_value', ''),
            
            # Loss details
            "loss_date_time": loss_datetime or datetime.utcnow(),
            "location": data['location'],
            "circumstances": data['circumstances'],
            "last_seen": data.get('last_seen', ''),
            
            # Additional information
            "identifiable_marks": data.get('identifiable_marks', ''),
            "witnesses": data.get('witnesses', ''),
            "previous_reports": data.get('previous_reports', ''),
            "attached_photos": data.get('attached_photos', []),
            
            # Status and metadata
            "status": "reported",  # reported, investigating, found, closed
            "declaration_accepted": data.get('declaration_accepted', False),
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }

        result = lost_items_collection.insert_one(lost_item_doc)

        # Emit socket event for real-time updates
        socketio.emit('new_lost_item_report', {
            'report_id': report_id,
            'user_name': lost_item_doc['user_name'],
            'item_name': lost_item_doc['item_name'],
            'location': lost_item_doc['location'],
            'timestamp': datetime.utcnow().isoformat()
        })

        return jsonify({
            "msg": "Lost item report submitted successfully",
            "report_id": report_id,
            "status": "reported"
        }), 201

    except Exception as e:
        print(f"Error reporting lost item: {e}")
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500

@app.route('/lost_items/my_reports', methods=['GET'])
@jwt_required()
def get_my_lost_reports():
    try:
        current_user_email = get_jwt_identity()
        user = users_collection.find_one({"email": current_user_email})
        if not user:
            return jsonify({"msg": "User not found"}), 404

        user_id = user["custom_id"]
        
        reports = list(lost_items_collection.find(
            {"user_id": user_id},
            {"_id": 0}
        ).sort("created_at", -1))

        # Convert datetime objects to strings
        for report in reports:
            for key, value in report.items():
                if isinstance(value, datetime):
                    report[key] = value.isoformat()

        return jsonify({"reports": reports}), 200

    except Exception as e:
        print(f"Error fetching lost reports: {e}")
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500

@app.route('/lost_items/<report_id>', methods=['GET'])
@jwt_required()
def get_lost_item_report(report_id):
    try:
        report = lost_items_collection.find_one(
            {"report_id": report_id},
            {"_id": 0}
        )
        
        if not report:
            return jsonify({"msg": "Report not found"}), 404

        # Convert datetime objects to strings
        for key, value in report.items():
            if isinstance(value, datetime):
                report[key] = value.isoformat()

        return jsonify(report), 200

    except Exception as e:
        print(f"Error fetching lost item report: {e}")
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500

@app.route('/lost_items/<report_id>/status', methods=['PUT'])
@jwt_required()
def update_lost_item_status(report_id):
    try:
        current_user_email = get_jwt_identity()
        data = request.get_json()
        
        new_status = data.get('status')
        valid_statuses = ['reported', 'investigating', 'found', 'closed']
        
        if new_status not in valid_statuses:
            return jsonify({"msg": f"Invalid status. Must be one of: {valid_statuses}"}), 400

        report = lost_items_collection.find_one({"report_id": report_id})
        if not report:
            return jsonify({"msg": "Report not found"}), 404

        # Check if user owns this report
        user = users_collection.find_one({"email": current_user_email})
        if user["custom_id"] != report['user_id']:
            return jsonify({"msg": "Not authorized to update this report"}), 403

        lost_items_collection.update_one(
            {"report_id": report_id},
            {
                "$set": {
                    "status": new_status,
                    "updated_at": datetime.utcnow()
                }
            }
        )

        return jsonify({
            "msg": f"Status updated to {new_status}",
            "report_id": report_id,
            "new_status": new_status
        }), 200

    except Exception as e:
        print(f"Error updating lost item status: {e}")
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500
@app.route('/lost_items/<report_id>', methods=['DELETE'])
@jwt_required()
def delete_lost_item(report_id):
    try:
        current_user_email = get_jwt_identity()
        user = users_collection.find_one({"email": current_user_email})
        if not user:
            return jsonify({"msg": "User not found"}), 404

        # Check if user owns this report
        report = lost_items_collection.find_one({"report_id": report_id})
        if not report:
            return jsonify({"msg": "Report not found"}), 404

        if user["custom_id"] != report['user_id']:
            return jsonify({"msg": "Not authorized to delete this report"}), 403

        # Delete the report
        result = lost_items_collection.delete_one({"report_id": report_id})

        if result.deleted_count > 0:
            return jsonify({
                "msg": "Lost item report deleted successfully",
                "report_id": report_id
            }), 200
        else:
            return jsonify({"msg": "Failed to delete report"}), 500

    except Exception as e:
        print(f"Error deleting lost item: {e}")
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500

if __name__ == '__main__':
    print("Starting Flask-SocketIO server with threading...")
    socketio.run(app, host='0.0.0.0', port=8000, debug=True)