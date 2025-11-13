# Dockerfile para o Frontend (React + Vite)
FROM node:18-alpine

# Definir diretório de trabalho
WORKDIR /app

# Copiar package.json e package-lock.json
COPY package*.json ./

# Instalar dependências
RUN npm install

# Copiar código da aplicação
COPY . .

# Expor porta
EXPOSE 5173

# Comando para iniciar a aplicação em modo desenvolvimento
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
