from flask import Flask,redirect,url_for,render_template,request,flash,session,send_file
import sqlite3
import bcrypt
import yagmail
import uuid
import base64
from cryptography.fernet import Fernet
import os




app = Flask(__name__,template_folder='templates')
app.secret_key = 'super super secret key'


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/logout")
def logout():
    session.pop('user_id', None)
    session.pop('master_key', None)
    session.pop('username', None)

    return redirect(url_for('index'))

@app.route("/delPasswd/<id>")
def delPasswd(id):
    try:
        con = sqlite3.connect("PassMan.db") 
        cur = con.cursor()
        cur.execute("DELETE FROM passwords WHERE id=(?) and user_id=(?)", [id,session["user_id"]])
        con.commit()


        print("Succcesful")
    except:
        con.rollback()
        print("Sorry failed")
        return redirect(url_for('home'))
    finally :
        con.close()

    return redirect(url_for('home'))

@app.route("/home")
def home():
    def decyrptingPasswd(master_key,passwd,salt):
        password = master_key
        key = bcrypt.kdf(password,salt,desired_key_bytes=32,rounds=4)
        key = base64.urlsafe_b64encode(key)
        f = Fernet(key)
        
        return f.decrypt(passwd)



    if not session.get("username"):
        return redirect(url_for('index'))
    try:
        user_id = session["user_id"] 
        con = sqlite3.connect("PassMan.db") 
        cur = con.cursor()
        cur.execute("SELECT email,password,salt,id,domain FROM passwords WHERE user_id=(?)", [user_id])
        records = [dict(email=row[0], passwd=(decyrptingPasswd(session["master_key"],row[1],row[2])).decode('ascii'),pass_id=row[3],domain=row[4] ) for row in cur.fetchall()]
        
            

        #print(hashes_pwd,clean_password.encode("utf-8"))
        print("Succcesful")
    except:
        con.rollback()
        print("Sorry failed")
        return redirect(url_for('index'))
    finally :
        con.close()    

        
    return render_template("home.html",records=records)



@app.route("/addPasswd", methods=["POST","GET"])
def addPasswd():
    if not session.get("username"):
        return redirect(url_for('index'))
    if request.method == "POST":
        
        user_id = session["user_id"]
        domain = request.form["domain"]
        email = request.form["email"]
        clean_password = request.form["password"]
        
        master_key = session["master_key"]
        salt = os.urandom(16)
        key = bcrypt.kdf(master_key,salt , desired_key_bytes=32, rounds=4)
        master_key2 = base64.urlsafe_b64encode(key)
        


        f = Fernet(master_key2)
        encrypted_password = f.encrypt(clean_password.encode("utf-8"))

        print(encrypted_password,master_key2)


        try:
            con = sqlite3.connect("PassMan.db") 
            cur = con.cursor()
            cur.execute("INSERT INTO passwords (user_id, email, password, salt, domain) VALUES ( ?, ?, ?, ?, ?)", (user_id, email, encrypted_password, salt, domain))
            con.commit()
            print("Succcesful")
  
        except:
            con.rollback()
            print("Sorry failed")
            return redirect(url_for('home'))
        finally :
            con.close()   
        
    return redirect(url_for('home'))


@app.route("/signin", methods=["POST","GET"])
def signin():
    if request.method == "POST":
        email = request.form["email"]
        clean_password = request.form["password"]

        try:
            con = sqlite3.connect("PassMan.db") 
            cur = con.cursor()
            cur.execute("SELECT username,password,id FROM users WHERE email=(?)", [email])
            fetchall  = cur.fetchall()
            hashes_pwd = fetchall[0][1]
            

            print(hashes_pwd,clean_password.encode("utf-8"))
            print("Succcesful")
        except:
            con.rollback()
            print("Sorry failed")
            return redirect(url_for('index'))
        finally :
            con.close()
        
        if bcrypt.checkpw(clean_password.encode("utf-8"),hashes_pwd ):
            session["username"] = fetchall[0][0]
            session["user_id"] = fetchall[0][2]
            session["master_key"] = hashes_pwd

            return redirect(url_for('home'))


    return redirect(url_for('index'))

@app.route("/signup", methods=["POST","GET"])
def signup():
    def sendActivationCode(email,code):
        user="passman.noreply@gmail.com"
        password="Test..12345"

        
        to = email
        subject = 'PassMan: Activation Code'
        body = 'Here is Activation Code: '+code
        html = '<h3>The report</h3>'
        yag = yagmail.SMTP(user, password)
        yag.send(to = to, subject = subject, contents = [body, html])
        return 

    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        clean_password = request.form["password"]

        bin_passwd = clean_password.encode("utf-8")
        salt = bcrypt.gensalt(rounds=4)
        hashed_password = bcrypt.hashpw(bin_passwd, salt)
        print(clean_password,bin_passwd,salt)

        activationCode = str(uuid.uuid4())


        try:
            con = sqlite3.connect("PassMan.db") 
            cur = con.cursor()
            cur.execute("INSERT INTO users (username, email, password, activeCode) VALUES (?, ?, ?, ?)", (username, email, hashed_password, activationCode))
            con.commit()
            print("Succcesful")
            sendActivationCode(email,activationCode)   
        except:
            con.rollback()
            print("Sorry failed")
            return redirect(url_for('index'))
        finally :
            con.close()
        
        return redirect("activation")

@app.route("/activation", methods=["POST","GET"])
def activation():
    if request.method == "POST":
        try:
            activeCode = request.form["activation"]
            con = sqlite3.connect("PassMan.db") 
            cur = con.cursor()
            cur.execute("UPDATE users SET activation = 1  WHERE activeCode = (?)", [activeCode])
            con.commit()
            
            print("Succcesful")  
            return redirect(url_for('index')) 
        except:
            con.rollback()
            print("Sorry failed",request.form["activation"],con,cur)
            return render_template("activation.html")
        finally :
            con.close()
    
    print("test")

    return render_template("activation.html")
    
    
            


if __name__ == "__main__":
    app.run()   