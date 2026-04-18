import smtplib

EMAIL = 'vatsalroy02@gmail.com'
APP_PASSWORD = 'ybkhwyhgydlkcxat'

try:
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
        server.login(EMAIL, APP_PASSWORD)
        print("✅ Login successful — Gmail SMTP is now working.")
except Exception as e:
    print("❌ Error:", e)
