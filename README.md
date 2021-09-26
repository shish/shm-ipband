shm-ipband
==========
A daemon which fetches a list of banned IPs from a Postgres database,
creates iptables rules to ban them, and updates the iptables rules each
time the database is updated.