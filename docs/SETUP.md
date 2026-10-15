# How to setup MMRS

1. You need a NATS server for discovery / communication with MMRS instances. 

   Protocol/integration is yet to be documented, read the source code for now.

2. Our setup involves Caddy for TLS termination and systemd to start/contain the daemon.
   - `mmrs.service` - sample systemd service file
   - `Caddyfile.example` - minimal Caddy configuration file for one tenant.
   - `.env.example` - sample `/etc/mmrs/mmrs.env`