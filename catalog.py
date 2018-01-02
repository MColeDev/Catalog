from flask import Flask, render_template, request, redirect, url_for, session
from flask import jsonify, flash, make_response
from flask import session as login_session
from passlib.hash import sha256_crypt
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, CatalogItem
import os
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests


app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog App"


engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
Session = DBSession()


# JSON APIs to view catalog and Information
@app.route('/catalog/JSON')
def catalogJSON():
    items = Session.query(CatalogItem).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/catalog/<int:id>/JSON')
def showItemJSON(id):
    item = Session.query(CatalogItem).filter_by(id=id).first()
    return jsonify(item=item.serialize)


@app.route('/', methods=['GET', 'POST'])
@app.route('/catalog', methods=['GET', 'POST'])
def catalogList():
    items = Session.query(CatalogItem).all()
    category = "All"
    if request.method == 'POST':

        if request.form['category'] != "All":
            items = Session.query(CatalogItem).filter_by(
                category=request.form['category']).all()

        return render_template(
            'showCatalog.html', items=items, category=request.form['category'])

    elif request.method == 'GET':
        return render_template(
            'showCatalog.html', items=items, category=category)


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Verify that is not already signed in
    if 'user' in session:
        flash("Your already signed in!")
        return redirect(url_for('catalogList'))

    if request.method == 'POST':

        if Session.query(User).filter_by(
                username=request.form['username']).first()is not None:

            checkUser = Session.query(User).filter_by(
                username=request.form['username']).first()
            # Compare entered password with stored encryption
            if sha256_crypt.verify(
                    request.form['password'], checkUser.password):
                session['user'] = request.form['username']
                session['logged_in'] = True
                return redirect(url_for('catalogList'))
            else:
                flash("Incorrect password!")
                return render_template('userLogin.html')
        else:
            flash("User not found!")
            return render_template('userLogin.html')

    if request.method == 'GET':
        return render_template('userLogin.html')


# User sign in through third party
@app.route('/glogin')
def showLogin():
    # Verify that user is not already signed in
    if 'user' in session:
        # Redirect user if already signed in
        flash("Your already signed in!!")
        return redirect(url_for('catalogList'))
    state = ''.join(random.choice(
        string.ascii_uppercase + string.digits)for x in xrange(32))
    login_session['state'] = state
    return render_template('googleLogin.html', STATE=state)


# register user without for use without third party
@app.route('/register', methods=['GET', 'POST'])
def createUser():
    items = Session.query(CatalogItem).all()
    users = Session.query(User).all()

    if request.method == 'POST':
        session.pop('user', None)
        # Verify that user name field is not blank
        if Session.query(User).filter_by(
                username=request.form['name']).first()is None:
            # Encrypt user password
            newuser = User(
                username=request.form['name'],
                password=sha256_crypt.encrypt(request.form['password']))
            Session.add(newuser)
            Session.commit()
            return redirect(url_for('login'))

    return render_template('registerUser.html', items=items, users=users)


@app.route('/dropsession')
def dropsession():

    access_token = login_session.get('access_token')
    if access_token is not None:
        return redirect(url_for('gdisconnect'))

    session.pop('user', None)
    session['logged_in'] = False

    return redirect(url_for('catalogList'))


@app.route('/create', methods=['GET', 'POST'])
def createItem():
    # Verify that user is signed in
    if 'user' in session:

        user = session['user']

        if request.method == 'POST':

            newItem = CatalogItem(
                name=request.form['name'],
                description=request.form['description'],
                category=request.form['category'], user=session['user'])
            Session.add(newItem)
            Session.commit()
            flash("new item added!")
            return redirect(url_for('catalogList'))

        elif request.method == 'GET':
            return render_template('createItem.html')

    else:
        return redirect(url_for('login'))


@app.route('/delete/<int:id>', methods=['GET', 'POST'])
def deleteItem(id):
    # Verify that user is signed in
    if 'user' in session:

        itemToDelete = Session.query(CatalogItem).filter_by(id=id).first()
        if session['user'] == itemToDelete.user:

            if request.method == 'POST':
                itemToDelete = Session.query(
                    CatalogItem).filter_by(id=id).first()
                Session.delete(itemToDelete)
                Session.commit()
                flash("Item Removed!")
                return redirect(url_for('catalogList'))

            elif request.method == 'GET':
                return render_template(
                    'deleteItem.html', id=id, item=itemToDelete)
        elif session['user'] != itemToDelete.user:
            return redirect(url_for('catalogList'))
    else:
        return redirect(url_for('login'))


@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def editItem(id):
    # Verify that user is signed in
    if 'user' in session:
        itemToEdit = Session.query(CatalogItem).filter_by(id=id).first()
        # Verify that user has authorization
        if session['user'] == itemToEdit.user:
            if request.method == 'POST':
                # Verify that a category has been selected
                if request.form['category'] != "None":
                    itemToEdit.name = request.form['name']
                    itemToEdit.description = request.form['description']
                    itemToEdit.category = request.form['category']
                    Session.add(itemToEdit)
                    Session.commit()
                    flash("Item updated!")
                    return redirect(url_for('catalogList'))
                else:
                    flash("Please select a category!")
                    return render_template(
                        'editItem.html', id=id, name=itemToEdit.name,
                        description=itemToEdit.description,
                        category=itemToEdit.category)
            elif request.method == 'GET':
                return render_template(
                    'editItem.html', id=id, name=itemToEdit.name,
                    description=itemToEdit.description,
                    category=itemToEdit.category)
        elif session['user'] != itemToEdit.user:
            return redirect(url_for('catalogList'))
    else:
        return redirect(url_for('login'))


@app.route('/product/<int:id>')
def showItem(id):
    item = Session.query(CatalogItem).filter_by(id=id).first()
    return render_template('showItem.html', item=item)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response
    session.pop('user', None)
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    session['user'] = data['email']

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    print "done!"
    session['logged_in'] = True
    return output


# Disconnect user from third party login
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % \
        login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'

        session.pop('user', None)

        session['logged_in'] = False

        return redirect(url_for('catalogList'))
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

if __name__ == '__main__':
        app.secret_key = os.urandom(24)
        app.debug = True
        app.run(host='0.0.0.0', port=5000)
