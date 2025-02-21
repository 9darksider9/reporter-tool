# Flask Web App Playbook

## **Getting Started**

### **1. Prerequisites**
Before running the web application, ensure you have the following installed:
- Python 3.13 (or compatible version)
- `pip` (Python package manager)
- `virtualenv`
- `Flask`, `Flask-Migrate`, `Flask-SQLAlchemy`, `Flask-Login`

If these are not installed, run:
```bash
pip install virtualenv
```

### **2. Clone the Repository**
If you haven't already cloned the project, do so by running:
```bash
git clone <repository_url>
cd reporter-tool/backend/webapp
```

### **3. Setup Virtual Environment**
```bash
python -m venv venv
source venv/bin/activate  # On Mac/Linux
venv\Scripts\activate    # On Windows
```

### **4. Install Dependencies**
```bash
pip install -r requirements.txt
```

## **Reset and Initialize Database**

### **Reset the Database (For a Fresh Start)**
If you need to reset the database and start over, use:
```bash
./reset_db.sh
```

This will:
1. Delete existing migrations and database.
2. Reinitialize the database.
3. Apply migrations.
4. Create a default admin user.

### **Verify Default Admin Exists**
After resetting, verify the admin account exists:
```bash
flask shell
```
Then run:
```python
from app.models import User
admin = User.query.filter_by(username="admin").first()
print(admin)
```
Expected output:
```
<User admin>
```
If `None` is returned, the admin user was not created properly.

### **Default Admin Credentials**
- **Username:** `admin`
- **Password:** `admin`
- **Email:** `admin@example.com`
- **Roles:** Admin (full access)

## **Starting the Web Application**

Run the Flask app using:
```bash
./run.sh
```
The app should be available at `http://localhost:5000`

## **Logging in as Admin**
1. Open `http://localhost:5000/login`
2. Enter the following credentials:
   - **Username:** `admin`
   - **Password:** `admin`
3. Click Login

If login fails:
- Ensure the database was properly reset and an admin user was created.
- Run `flask shell` and check if the admin exists as shown above.

## **Every Time You Resume Working on This Project**
Whenever you take a break and return to development, follow these steps:

1. **Activate Virtual Environment:**
```bash
source venv/bin/activate  # Mac/Linux
venv\Scripts\activate    # Windows
```

2. **Start the Flask App:**
```bash
./run.sh
```

3. **Verify Database is Set Up:**
If needed, reset the database:
```bash
./reset_db.sh
```

4. **Login as Admin and Verify UI is Working:**
Go to `http://localhost:5000/login` and sign in with `admin` credentials.

## **How to Provide Code for Further Development**
To ensure continuity when prompting me for code modifications, follow these steps:

1. **Label the Code**
   - Specify which file the code belongs to.
   - Example:
     ```
     File: app/models.py
     (paste code here)
     ```

2. **State the Change You Want**
   - Be clear on what needs to be added/modified.
   - Example:
     ```
     I need to add a `last_modified` field to the `User` model and update it whenever user details are changed.
     ```

3. **Ask for a Full Rewrite if Needed**
   - If an entire section needs reworking, specify that you need a full rewrite.
   - Example:
     ```
     Can you rewrite `auth_routes.py` to fix the login redirect issue?
     ```

By following these steps, we can efficiently iterate and build upon what we’ve already created. 🚀