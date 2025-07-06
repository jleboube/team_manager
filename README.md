# ====================================
# DEPLOYMENT INSTRUCTIONS
# ====================================

# Step 1: Create the following directory structure on your VM:
# baseball-manager/
# ├── backend/
# │   ├── Dockerfile
# │   ├── package.json
# │   ├── server.js
# │   └── init.sql
# ├── frontend/
# │   └── index.html
# ├── nginx/
# │   └── nginx.conf
# ├── docker-compose.yml
# ├── .env
# └── deploy.sh

# Step 2: Copy the content above into each respective file

# Step 3: Make deploy script executable and run:
# chmod +x deploy.sh
# ./deploy.sh

# Step 4: Access your application:
# http://your-vm-ip/

# This simplified version eliminates the React build complexity
# and uses a single HTML file with vanilla JavaScript that
# connects to the real backend API.