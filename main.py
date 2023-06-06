# main.py
import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from flask import Flask, render_template, Response, redirect, request, session, abort, url_for
import mysql.connector
import hashlib
import shutil
import datetime
import random
from random import randint

from flask_mail import Mail, Message
from flask import send_file
from werkzeug.utils import secure_filename
from PIL import Image
import stepic
import urllib.parse
from urllib.request import urlopen
import webbrowser
import socket    

mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="",
  charset="utf8",
  database="virtual_assistant"

)
app = Flask(__name__)
##session key
app.secret_key = 'abcdef'

UPLOAD_FOLDER = 'static/upload'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
#####
@app.route('/', methods=['GET', 'POST'])
def index():
    msg=""

    #txt = "hai hello"
    #result = hashlib.md5(txt.encode())
    #print(result.hexdigest())
    #string = "freeCodeCamp"
    #print(string[4:8])
    
    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        cursor = mydb.cursor()
        cursor.execute('SELECT * FROM dr_register WHERE uname = %s AND pass = %s AND status=1', (uname, pwd))
        account = cursor.fetchone()
        if account:
            session['username'] = uname
            return redirect(url_for('upload'))
        else:
            msg = 'Incorrect username/password! or access not provided'
    return render_template('index.html',msg=msg)

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg=""

    
    
    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        cursor = mydb.cursor()
        cursor.execute('SELECT * FROM va_admin WHERE username = %s AND password = %s', (uname, pwd))
        account = cursor.fetchone()
        if account:
            session['username'] = uname
            return redirect(url_for('admin'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('login.html',msg=msg)

@app.route('/login_owner', methods=['GET', 'POST'])
def login_owner():
    msg=""

    
    
    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        cursor = mydb.cursor()
        cursor.execute('SELECT * FROM va_register WHERE uname = %s AND pass = %s', (uname, pwd))
        account = cursor.fetchone()
        if account:
            session['username'] = uname
            return redirect(url_for('upload'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('login_owner.html',msg=msg)

@app.route('/login_user', methods=['GET', 'POST'])
def login_user():
    msg=""

    
    
    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        cursor = mydb.cursor()
        cursor.execute('SELECT * FROM va_user WHERE uname = %s AND pass = %s', (uname, pwd))
        account = cursor.fetchone()
        if account:
            session['username'] = uname
            return redirect(url_for('userhome'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('login_user.html',msg=msg)

@app.route('/login_kgc', methods=['GET', 'POST'])
def login_kgc():
    msg=""

    
    
    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        cursor = mydb.cursor()
        cursor.execute('SELECT * FROM va_reg_kgc WHERE uname = %s AND pass = %s', (uname, pwd))
        account = cursor.fetchone()
        if account:
            session['username'] = uname
            return redirect(url_for('kgc_home'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('login_kgc.html',msg=msg)

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg=""
    mycursor = mydb.cursor()
    mycursor.execute("SELECT max(id)+1 FROM va_register")
    maxid = mycursor.fetchone()[0]

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
            
    if maxid is None:
        maxid=1
    if request.method=='POST':
        name=request.form['name']
        mobile=request.form['mobile']
        email=request.form['email']
        city=request.form['city']
        uname=request.form['uname']
        pass1=request.form['pass']
        cursor = mydb.cursor()

        cursor.execute('SELECT count(*) FROM va_register WHERE uname = %s ', (uname,))
        cnt = cursor.fetchone()[0]
        if cnt==0:
            result = hashlib.md5(uname.encode())
            key=result.hexdigest()
            pbkey=key[0:8]
            prkey=key[8:16]
            sql = "INSERT INTO va_register(id,name,mobile,email,city,public_key,private_key,uname,pass,rdate,status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            val = (maxid,name,mobile,email,city,pbkey,prkey,uname,pass1,rdate,'0')
            cursor.execute(sql, val)
            mydb.commit()            
            print(cursor.rowcount, "Registered Success")
            result="sucess"

            ##send mail
            mess="Owner:"+uname+", Public Key:"+pbkey+", Private Key:"+prkey
            
            #if cursor.rowcount==1:
            return redirect(url_for('index'))
        else:
            msg='Already Exist'
    return render_template('register.html',msg=msg)


def encrypt(pk, size, q, t, poly_mod, m, std1): 
    """Encrypt an integer vector pt.
    Args:
        pk: public-key.
        size: size of polynomials.
        q: ciphertext modulus.
        t: plaintext modulus.
        poly_mod: polynomial modulus.
        m: plaintext message, as an integer vector (of length <= size) with entries mod t.
    Returns:
        Tuple representing a ciphertext.
    """
    m = np.array(m + [0] * (size - len(m)), dtype=np.int64) % t
    delta = q // t
    scaled_m = delta * m
    e1 = gen_normal_poly(size, 0, std1)
    e2 = gen_normal_poly(size, 0, std1)
    u = gen_binary_poly(size)
    ct0 = polyadd(
        polyadd(
            polymul(pk[0], u, q, poly_mod),
            e1, q, poly_mod),
        scaled_m, q, poly_mod
    )
    ct1 = polyadd(
        polymul(pk[1], u, q, poly_mod),
        e2, q, poly_mod
    )
    return (ct0, ct1)

def decrypt(sk, q, t, poly_mod, ct):
    """Decrypt a ciphertext.
    Args:
        sk: secret-key.
        size: size of polynomials.
        q: ciphertext modulus.
        t: plaintext modulus.
        poly_mod: polynomial modulus.
        ct: ciphertext.
    Returns:
        Integer vector representing the plaintext.
    """
    scaled_pt = polyadd(
        polymul(ct[1], sk, q, poly_mod),
        ct[0], q, poly_mod
    )
    decrypted_poly = np.round(t * scaled_pt / q) % t
    return np.int64(decrypted_poly)
############s
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    msg=""
    act=""
    if 'username' in session:
        uname = session['username']
    print(uname)

    cursor1 = mydb.cursor()
    cursor1.execute('SELECT * FROM va_register')
    data=cursor1.fetchall()

    return render_template('admin.html',data=data)

    
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    msg=""
    act=""
    if 'username' in session:
        uname = session['username']
    print(uname)

    cursor1 = mydb.cursor()
    cursor1.execute('SELECT * FROM va_register where uname=%s',(uname, ))
    rr=cursor1.fetchone()
    name=rr[1]
    pbkey = rr[5]
    email = rr[3]
    #pbkey=data1[9]

    ff=open("bc.txt","r")
    bc=ff.read()
    ff.close()

    
    
    
    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    
    if request.method=='POST':
        file_content=request.form['content']
        pbk=request.form['pbk']

        if pbk==pbkey:

            mycursor = mydb.cursor()
            mycursor.execute("SELECT max(id)+1 FROM va_user_files")
            maxid = mycursor.fetchone()[0]
            if maxid is None:
                maxid=1

            


            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            
            file_type = file.content_type
            # if user does not select file, browser also
            # submit an empty part without filename
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if file:
                fname = "F"+str(maxid)+file.filename
                filename = secure_filename(fname)
                
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            

            
            ##encryption
            password_provided = pbkey # This is input in the form of a string
            password = password_provided.encode() # Convert to type bytes
            salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))

            input_file = 'static/upload/'+fname
            output_file = 'static/upload/E'+fname
            with open(input_file, 'rb') as f:
                data = f.read()

            fernet = Fernet(key)
            encrypted = fernet.encrypt(data)

            with open(output_file, 'wb') as f:
                f.write(encrypted)
                
            
            
            ##store
            sql = "INSERT INTO va_user_files(id,uname,file_type,file_content,upload_file,rdate) VALUES (%s, %s, %s, %s, %s, %s)"
            val = (maxid,uname,file_type,file_content,filename,rdate)
            mycursor.execute(sql,val)
            mydb.commit()
            
            msg="Uploaded success.."
            return redirect(url_for('upload_st',fname=filename))
            
        else:
            msg="Public Key Incorrect!"
    
    
    return render_template('upload.html',msg=msg,name=name,bc=bc)

@app.route('/upload_st', methods=['GET', 'POST'])
def upload_st():
    msg=""
    act=""
    if 'username' in session:
        uname = session['username']
    print(uname)

    fname = request.args.get('fname')
    
    cursor1 = mydb.cursor()
    cursor1.execute('SELECT * FROM va_register where uname=%s',(uname, ))
    rr=cursor1.fetchone()
    name=rr[1]
    pbkey = rr[5]
    email = rr[3]
    #pbkey=data1[9]

    ff=open("bc.txt","r")
    bc=ff.read()
    ff.close()
    data1="Owner: "+uname+", File Upload, File: "+fname


    return render_template('upload_st.html',msg=msg,name=name,bc=bc,data1=data1)


@app.route('/view_files', methods=['GET', 'POST'])
def view_files():
    msg=""
    act = request.args.get('act')
    if 'username' in session:
        uname = session['username']
    print(uname)

    cursor1 = mydb.cursor()
    cursor1.execute('SELECT * FROM va_register where uname=%s',(uname, ))
    rr=cursor1.fetchone()
    name=rr[1]

    cursor1.execute('SELECT * FROM va_user_files where uname=%s',(uname, ))
    data=cursor1.fetchall()

    if act=="del":
        did = request.args.get('did')
        cursor1.execute('delete from va_user_files where id=%s', (did,))
        mydb.commit()

    return render_template('view_files.html',msg=msg,name=name,data=data)

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    uname=""
    msg=""
    act = request.args.get('act')
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM va_register where uname=%s",(uname,))
    value = mycursor.fetchone()
    dname=value[1]
    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
        
    if request.method=='POST':
        
        name=request.form['name']
        gender=request.form['gender']
        dob=request.form['dob']
        mobile=request.form['mobile']
        email=request.form['email']
        user=request.form['user']
        pass1=request.form['pass']
        location=request.form['location']
        desig=request.form['desig']
        

        
        now = datetime.datetime.now()
        rdate=now.strftime("%d-%m-%Y")
        mycursor = mydb.cursor()

        mycursor.execute('SELECT count(*) FROM va_user WHERE uname = %s ', (user,))
        cnt = mycursor.fetchone()[0]
        if cnt==0:
            
            mycursor.execute("SELECT max(id)+1 FROM va_user")
            maxid = mycursor.fetchone()[0]
            if maxid is None:
                maxid=1

            
            sql = "INSERT INTO va_user(id, name, owner, gender, dob, mobile, email,location, desig, uname, pass) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            val = (maxid, name, uname, gender, dob, mobile, email, location, desig, user, pass1)
            act="success"
            mycursor.execute(sql, val)
            mydb.commit()            
            print(mycursor.rowcount, "record inserted.")
            ##send mail
            message="User Account - Data Owner:"+uname+", Username: "+user+", Password: "+pass1
            url="http://iotcloud.co.in/testmail/sendmail.php?email="+email+"&message="+message
            webbrowser.open_new(url)
            act="1"
            return redirect(url_for('add_user',act=act))
        else:
            msg="Already Exist!"

    mycursor.execute("SELECT * FROM va_user where owner=%s",(uname,))
    data = mycursor.fetchall()
    
    return render_template('add_user.html',value=value,act=act,data=data,dname=dname,msg=msg)

@app.route('/reg_kgc', methods=['GET', 'POST'])
def reg_kgc():
    msg=""
    mycursor = mydb.cursor()
    mycursor.execute("SELECT max(id)+1 FROM va_reg_kgc")
    maxid = mycursor.fetchone()[0]

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
            
    if maxid is None:
        maxid=1
    if request.method=='POST':
        name=request.form['name']
        mobile=request.form['mobile']
        email=request.form['email']
        
        uname=request.form['uname']
        pass1=request.form['pass']
        cursor = mydb.cursor()

        cursor.execute('SELECT count(*) FROM va_reg_kgc WHERE uname = %s ', (uname,))
        cnt = cursor.fetchone()[0]
        if cnt==0:

            result = hashlib.md5(uname.encode())
            key=result.hexdigest()
            pbkey=key[0:8]
            prkey=key[8:16]
            sql = "INSERT INTO va_reg_kgc(id,name,mobile,email,uname,pass) VALUES (%s, %s, %s, %s, %s, %s)"
            val = (maxid,name,mobile,email,uname,pass1)
            cursor.execute(sql, val)
            mydb.commit()            
            print(cursor.rowcount, "Registered Success")
            result="sucess"

        
        
            #if cursor.rowcount==1:
            return redirect(url_for('index'))
        else:
            msg='Already Exist'
    return render_template('reg_kgc.html',msg=msg)

@app.route('/kgc_home', methods=['GET', 'POST'])
def kgc_home():
    msg=""
    act=""
    if 'username' in session:
        uname = session['username']
    print(uname)

    cursor = mydb.cursor()
    cursor.execute('SELECT count(*) FROM va_register where uname=%s',(uname, ))
    cnt=cursor.fetchone()[0]

    cursor.execute('SELECT * FROM va_register where uname=%s',(uname, ))
    dd=cursor.fetchone()
    email=dd[3]

    if request.method=='POST':
        if cnt>0:
            
            result = hashlib.md5(uname.encode())
            key=result.hexdigest()
            pbkey=key[0:8]
            prkey=key[8:16]
            cursor.execute('update va_register set public_key=%s,private_key=%s where uname = %s', (pbkey,prkey,uname))
            mydb.commit()
            ##send mail
            message="Data Owner:"+uname+", Public Key:"+pbkey+", Private Key:"+prkey
            url="http://iotcloud.co.in/testmail/sendmail.php?email="+email+"&message="+message
            webbrowser.open_new(url)
            msg="Key Generated and sent to your email.."
            act="1"
        else:
            act="1"
            msg="Data owner does not exist!"

    return render_template('kgc_home.html',msg=msg,act=act,uname=uname)

@app.route('/kgc_user', methods=['GET', 'POST'])
def kgc_user():
    msg=""
    act=""
    if 'username' in session:
        uname = session['username']
    print(uname)

    cursor = mydb.cursor()
    

    cursor.execute('SELECT * FROM va_register where uname=%s',(uname, ))
    dd=cursor.fetchone()
    dname=dd[1]

    if request.method=='POST':
        user=request.form['user']
        name=request.form['name']
        mobile=request.form['mobile']
        email=request.form['email']
        
        cursor.execute('SELECT count(*) FROM va_user where uname=%s',(user, ))
        cnt=cursor.fetchone()[0]
        if cnt>0:

            cursor.execute('SELECT count(*) FROM va_user_kgc where uname=%s',(user, ))
            cnt2=cursor.fetchone()[0]
            if cnt2==0:
            
                result = hashlib.md5(user.encode())
                key=result.hexdigest()
                pbkey=key[0:8]
                prkey=key[8:16]

                cursor.execute("SELECT max(id)+1 FROM va_user_kgc")
                maxid = cursor.fetchone()[0]
                if maxid is None:
                    maxid=1
                
                sql = "INSERT INTO va_user_kgc(id,owner,name,mobile,email,uname,public_key,private_key) VALUES (%s,%s, %s, %s, %s, %s, %s, %s)"
                val = (maxid,uname,name,mobile,email,user,pbkey,prkey)
                cursor.execute(sql, val)
                mydb.commit()
                ##
                cursor.execute('update va_user set public_key=%s,private_key=%s where uname = %s', (pbkey,prkey,user))
                mydb.commit()
                ##send mail
                message="Data User:"+user+", Owner: "+uname+", Public Key:"+pbkey+", Private Key:"+prkey
                url="http://iotcloud.co.in/testmail/sendmail.php?email="+email+"&message="+message
                webbrowser.open_new(url)
                msg="Key Generated and sent to email.."
                act="1"
            else:
                msg="Already Key Sent!"
                act="1"
                
                    
        else:
            act="1"
            msg="Data user does not exist!"

    cursor.execute("SELECT * FROM va_user_kgc where owner=%s",(uname,))
    data = cursor.fetchall()
    return render_template('kgc_user.html',msg=msg,act=act,uname=uname,data=data)

@app.route('/userhome', methods=['GET', 'POST'])
def userhome():
    msg=""
    act=""
    if 'username' in session:
        uname = session['username']
    print(uname)

    cursor = mydb.cursor()
    cursor.execute('SELECT * FROM va_user where uname=%s',(uname, ))
    rr=cursor.fetchone()
    name=rr[1]
    owner=rr[2]

    
    cursor.execute("SELECT * FROM va_user_files f,va_share s where s.fid=f.id && s.uname=%s",(uname,))
    data = cursor.fetchall()

    return render_template('userhome.html',msg=msg,act=act,name=name,data=data)

@app.route('/file_verify', methods=['GET', 'POST'])
def file_verify():
    msg=""
    act=""
    fname = request.args.get('fname')
    fid = request.args.get('fid')
    if 'username' in session:
        uname = session['username']
    print(uname)

    cursor = mydb.cursor()
    cursor.execute('SELECT * FROM va_user where uname=%s',(uname, ))
    rr=cursor.fetchone()
    name=rr[1]
    owner=rr[2]

    cursor.execute('SELECT * FROM va_user_kgc where uname=%s',(uname, ))
    rr2=cursor.fetchone()
    pbkey2=rr2[5]
    
    cursor.execute('SELECT * FROM va_register where uname=%s',(owner, ))
    rrd=cursor.fetchone()
    pbk=rrd[5]

    
    cursor.execute("SELECT * FROM va_user_files where uname=%s",(owner,))
    data = cursor.fetchall()
    ###Decrypt by owner pbk#
    password_provided = pbk # This is input in the form of a string
    password = password_provided.encode() # Convert to type bytes
    salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    input_file = 'static/upload/e'+fname
    output_file = 'static/decrypted/'+fname
    with open(input_file, 'rb') as f:
        data = f.read()

    fernet = Fernet(key)
    encrypted = fernet.decrypt(data)

    with open(output_file, 'wb') as f:
        f.write(encrypted)

    #######################################
    ##encrypt by user pbk
    password_provided = pbkey2 # This is input in the form of a string
    password = password_provided.encode() # Convert to type bytes
    salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))

    input_file = 'static/upload/'+fname
    output_file = 'static/encrypted/E'+fname
    with open(input_file, 'rb') as f:
        data = f.read()

    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)

    with open(output_file, 'wb') as f:
        f.write(encrypted)
   
    ##############

        

            
    return render_template('file_verify.html',msg=msg,act=act,name=name,data=data,fname=fname,fid=fid)

@app.route('/access', methods=['GET', 'POST'])
def access():
    uname=""
    msg=""
    
    fid = request.args.get('fid')
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM va_register where uname=%s",(uname,))
    value = mycursor.fetchone()

    mycursor.execute("SELECT * FROM va_user where owner=%s",(uname,))
    data = mycursor.fetchall()

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
        
    if request.method=='POST':
        
        uid=request.form.getlist('uid[]')
        #print(uid)
        for ss in uid:
            mycursor.execute("SELECT count(*) FROM va_share where uname=%s && id=%s",(ss,fid))
            cnt = mycursor.fetchone()[0]
            if  cnt==0:
                mycursor.execute("SELECT max(id)+1 FROM va_share")
                maxid = mycursor.fetchone()[0]
                if maxid is None:
                    maxid=1

                
                sql = "INSERT INTO va_share(id, fid, uname, rdate) VALUES (%s, %s, %s, %s)"
                val = (maxid, fid, ss, rdate)
                act="success"
                mycursor.execute(sql, val)
                mydb.commit()
        return redirect(url_for('view_files'))


    mycursor.execute("SELECT * FROM va_share where fid=%s",(fid,))
    data2 = mycursor.fetchall()
    
    return render_template('access.html',value=value,data=data,data2=data2)

@app.route('/file_down', methods=['GET', 'POST'])
def file_down():
    msg=""
    act=""
    fname = request.args.get('fname')
    fid = request.args.get('fid')
    if 'username' in session:
        uname = session['username']
    print(uname)

    cursor = mydb.cursor()
    cursor.execute('SELECT * FROM va_user where uname=%s',(uname, ))
    rr=cursor.fetchone()
    name=rr[1]
    owner=rr[2]

    ff=open("bc.txt","r")
    bc=ff.read()
    ff.close()

    rn1=randint(1000,9999)
    ff=open("key.txt","w")
    ff.write(str(rn1))
    ff.close()
    
    data1="User: "+uname+", File Download, File: "+fname

    return render_template('file_down.html',fname=fname,fid=fid,bc=bc,data1=data1)

@app.route('/file_page', methods=['GET', 'POST'])
def file_page():
    msg=""
    data1=""
    fname = request.args.get('fname')
    fid = request.args.get('fid')
    act = request.args.get('act')
    if 'username' in session:
        uname = session['username']
    print(uname)

    cursor = mydb.cursor()
    cursor.execute('SELECT * FROM va_user where uname=%s',(uname, ))
    rr=cursor.fetchone()
    name=rr[1]
    owner=rr[2]
    mobile=rr[5]

    cursor.execute('SELECT * FROM va_user_kgc where uname=%s',(uname, ))
    rr2=cursor.fetchone()
    prk=rr2[6]
    pbk=rr2[5]

    ff=open("bc.txt","r")
    bc=ff.read()
    ff.close()

    ff=open("key.txt","r")
    otp=ff.read()
    ff.close()

    
    st=""
    if request.method=='POST':
        skey=request.form['skey']
        if prk==skey:
            st="1"
            ###Decrypt by user pbk#
            password_provided = pbk # This is input in the form of a string
            password = password_provided.encode() # Convert to type bytes
            salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            input_file = 'static/encrypted/e'+fname
            output_file = 'static/decrypted/'+fname
            with open(input_file, 'rb') as f:
                data = f.read()

            fernet = Fernet(key)
            encrypted = fernet.decrypt(data)

            with open(output_file, 'wb') as f:
                f.write(encrypted)
            data1="User: "+uname+", File Download, File: "+fname 
        else:
            st="2"     
            data1="User: "+uname+", Attack found, File: "+fname

    return render_template('file_page.html',fname=fname,fid=fid,bc=bc,data1=data1,act=act,st=st,otp=otp,mobile=mobile)




@app.route('/down', methods=['GET', 'POST'])
def down():
    fn = request.args.get('fname')
    path="static/decrypted/"+fn
    return send_file(path, as_attachment=True)


@app.route('/logout')
def logout():
    # remove the username from the session if it is there
    session.pop('username', None)
    return redirect(url_for('index'))




if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
