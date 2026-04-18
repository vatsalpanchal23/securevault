UPDATE security_logs
SET risk_level = 'HIGH'
WHERE event = 'LOGIN_FAILED'
  AND id > 0;












































