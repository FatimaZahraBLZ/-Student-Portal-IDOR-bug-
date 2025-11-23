
  # Student Document Dashboard

  This is a code bundle for Student Document Dashboard. The original project is available at https://www.figma.com/design/UmdHXSFqj7G1pFPnIK4ZxM/Student-Document-Dashboard.

  ## Running the code

  Run `npm install` to install the dependencies.

  and also `npm install --save-dev @types/react @types/react-dom` to get rid of the error of the react type.

  Run `npm run dev` to start the development server.

  Before running the backend python first install the requirements `pip install -r requirements.txt` 

  Then run the backend `python app.py`

  To run the app in the burp browser run the app with the commande `npm run dev -- --host 0.0.0.0`


#  PART 1 — The ROOT Cause of the IDOR in This App

**IDOR = Insecure Direct Object Reference**
It happens when a user can access a resource by directly referencing it (`file_id`, `user_id`, `doc_id`) **without authorization checks**.

This application contains two explicit vulnerabilities that intentionally cause IDOR.

---

##  VULNERABILITY #1 — “User chooses ANY user_id” (List endpoint)

**File:** `app.py` → `/api/documents` endpoint

```python
@app.route("/api/documents", methods=["GET"])
@auth_required
def list_documents():
    user_id = request.args.get("user_id")

    # vulnerable: user sends any user_id and sees their files
    docs = Document.query.filter_by(user_id=user_id).all()

    return jsonify([serialize_document(d) for d in docs])
```

###  Why this is vulnerable

* The backend **trusts the `user_id` sent by the frontend**.
* The assumption is: “If React sends `user_id=2`, then the user must be user 2.”
* But a malicious user can modify the request in Burp Suite:

```
GET /api/documents?user_id=1   (their own ID)
→ attacker changes to:
GET /api/documents?user_id=2   (another user’s ID)
```

###  Impact

The attacker can view **all documents belonging to any user**.

This is **broken access control → IDOR**.

---

## VULNERABILITY #2 — “Download any file by guessing doc_id”

**File:** `app.py` → `/api/documents/download`

```python
@app.route("/api/documents/download", methods=["GET"])
@auth_required
def download_document():
    doc_id = request.args.get("file_id", type=int)
    ...
    doc = Document.query.get(doc_id)

    # vulnerable: no check if the file belongs to logged user
    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        doc.stored_name,
        as_attachment=True
    )
```

###  Why this is vulnerable

The attacker only needs to guess or enumerate `file_id` values.

Because IDs are predictable (`1, 2, 3, 4...`), they can simply try:

```
GET /api/documents/download?file_id=1
GET /api/documents/download?file_id=2
GET /api/documents/download?file_id=3
```

###  Impact

The attacker can **download another student’s file**, such as assignments or private documents.

---

##  BONUS — Vulnerability #3 (Upload)

```python
user_id = request.form.get("user_id")
```

### Meaning:

A malicious user can upload a document **pretending to be another user**.

This is a minor vulnerability, but still part of the larger **broken access control** group.

---

#  PART 2 — Why These Bugs Are Intentional

Our project requirements :

* Build an insecure version
* Break it
* Fix it

To achieve this, the code intentionally includes:

### 1. **Predictable identifiers** (`1, 2, 3, 4`)

Makes enumeration trivial.

### 2. **No ownership checks**

No code like:

```python
if doc.user_id != current_user.id:
    return 403
```

This is the **core** of IDOR.

### 3. **Trusting user input (`user_id`)**

Allows an attacker to impersonate another user by simply modifying the request.

These patterns are **classic real-world vulnerabilities**

#  PART 3 — How the IDOR Bug Connects With the React App

**File:** `App.tsx`

The frontend sends:

```ts
fetch(`${API_BASE_URL}/api/documents?user_id=${userId}`)
```

This means:

* The frontend **blindly sends `user_id`**
* The backend **blindly trusts it**

A malicious user can edit the request in Burp Suite:

```
user_id=2
```

Our backend does **not** verify that the logged-in user actually *is* user 2.

---

#  PART 4 — Summary of the Entire IDOR Mechanism

###  Step 1 — Attacker logs in

They receive a valid token.

###  Step 2 — Attacker modifies `user_id` or `file_id` in Burp Suite

Backend does **not** verify:

* If this user owns the file
* If the file is allowed to be downloaded
* If the `user_id` matches the authenticated user

###  Step 3 — Server returns the file

This behavior is **IDOR**.

---

#  PART 5 — Most Important Vulnerable Functions

###  `list_documents()` → IDOR #1

Accepts **any** user_id.

###  `download_document()` → IDOR #2

Returns a file **without checking document ownership**.

###  `upload_document()` → Minor IDOR #3

Allows uploading documents “as” any user.

---

#  PART 6 — What Will Be Fixed in the Secure Version

###  Fix 1 — Extract user_id from the AuthToken

You already authenticate using tokens:

```python
auth = AuthToken.query.filter_by(token=token).first()
current_user_id = auth.user_id
```

Then replace:

```python
docs = Document.query.filter_by(user_id=user_id)
```

with:

```python
docs = Document.query.filter_by(user_id=current_user_id)
```

---

###  Fix 2 — Add ownership checks during download

```python
if doc.user_id != current_user_id:
    return jsonify({"error": "Forbidden"}), 403
```

---

###  Fix 3 — Remove `user_id` from the frontend

The frontend should **never** send `user_id` again.

The backend should always infer the user from the authentication token.
