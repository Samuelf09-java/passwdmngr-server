# Password Manager Server

Supported operating systems:
- linux x86_64 (systemd)

## Installation

Run:
```
git clone https://github.com/Samuelf09-Java/passwdmngr-server.git
cd passwdmngr-server
make
sudo make install
sudo systemctl start passdwmngrd.service
# If you want to enable the server at boot:
sudo systemctl enable passwdmngrd.service
```

View logs: ```sudo journalctl -u passwdmngrd -f```

- Note: This server is currently configured to run as root; however, I will look into making it non-privileged once I finish the basic structure

## SMTP Verification

This server stores user data by email & user id; however, SMTP verification via six-digit codes sent to the provided email address is disabled by default. To configure SMTP verification, enter your credentials in /var/lib/passwdmngrd/smtp.conf and change use_smtp_verification to true. If smtp is not configured properly and libcurl cannot send the email, the server will return an error on every CREATEACCOUNT request.
