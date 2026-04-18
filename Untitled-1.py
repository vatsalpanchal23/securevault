@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM passwords WHERE user_id = %s", (session['user_id'],))
    passwords = cursor.fetchall()
    
    # Decrypt each password
    for p in passwords:
        p['service_password'] = decrypt_password(p['service_password'])
    
    cursor.close()
    conn.close()
    return render_template('dashboard.html', passwords=passwords)

@app.route('/add_password', methods=['POST'])
def add_password():
    if 'user_id' not in session:
        return redirect('/')

    service = request.form['service']
    service_username = request.form['service_username']
    service_password = encrypt_password(request.form['service_password'])

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO passwords (user_id, service, service_username, service_password)
        VALUES (%s, %s, %s, %s)
    """, (session['user_id'], service, service_username, service_password))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect('/dashboard')
