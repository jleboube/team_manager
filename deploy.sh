#!/bin/bash

echo "🚀 Deploying Baseball Team Manager (Simplified)..."

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p uploads
mkdir -p postgres_data

# Set permissions
chmod 755 uploads
chmod 700 postgres_data

# Stop any existing containers
echo "🛑 Stopping existing containers..."
docker compose down

# Clean up old images
echo "🧹 Cleaning up..."
docker system prune -f

# Build and start services
echo "🔨 Building and starting services..."
docker compose up --build -d

# Wait for services
echo "⏳ Waiting for services to start..."
sleep 20

# Check status
echo "🔍 Checking service status..."
docker compose ps

# Show logs
echo "📋 Recent logs:"
docker compose logs --tail=20

echo ""
echo "✅ Deployment complete!"
echo ""
echo "🌐 Application URLs:"
echo "   Frontend: http://localhost"
echo "   API: http://localhost/api"
echo "   Health Check: http://localhost/api/health"
echo ""
echo "🔑 Demo Login Credentials:"
echo "   Coach/Admin: coach@team.com / password"
echo "   Player: player@team.com / password"
echo "   Parent: parent@team.com / password"
echo "   Registration Code: TEAM123"
echo ""
echo "🏆 Your baseball team management application is ready!"
