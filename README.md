# LLM-Network-Scanner

Current setup allows users to utilize Natura Language Processing done by OpenAI and:
- Create a custom welcoming banner for application
- Check the current status of given hosts (online/offline)
- Scan online hosts for open ports
- Aggressively scan open ports
- Find out best tools to dive deeper into specific services

TBD:
- Add functionality to distinguish ports for different hosts

## Testing

We have used Docker environement with [opencanary](https://github.com/thinkst/opencanary) build to locally test out Network Scanner .

```bash
sudo docker-compose up latest
```

Opencanary config files:

```bash
# docker-compose.yml
###
image: "opencanary"
#network_mode: "host"
ports:
# FTP
- "21:21"
# SSH
- "22:22"
# TFTP
- "69:69"
# HTTP
- "80:80"
# MYSQL
- "3306:3306"
# RDP
- "3389:3389"

# .opencanary.conf
"tftp.enabled": true,
"rdp.enabled": true,
"ssh.enabled": true,
"mysql.enabled": true,
"https.enabled": false,
"ftp.enabled": true,
"http.enabled": true,
```