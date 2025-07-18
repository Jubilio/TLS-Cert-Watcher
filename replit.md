# TLS Certificate Checker

## Overview

This is a full-stack web application that provides TLS certificate checking functionality. It consists of a React frontend with a Node.js/Express backend, allowing users to check SSL/TLS certificates for websites and view the results. The application also includes an NSE (Nmap Scripting Engine) script for certificate verification.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: React 18 with TypeScript
- **UI Library**: Radix UI components with shadcn/ui styling
- **Styling**: Tailwind CSS with custom CSS variables for theming
- **Routing**: Wouter for client-side routing
- **State Management**: TanStack Query (React Query) for server state management
- **Build Tool**: Vite for fast development and optimized builds

### Backend Architecture
- **Runtime**: Node.js with Express.js framework
- **Language**: TypeScript with ES modules
- **Database**: PostgreSQL with Drizzle ORM
- **Database Driver**: Neon Database serverless driver
- **Session Management**: Connect-pg-simple for PostgreSQL session storage
- **Development**: tsx for TypeScript execution in development

## Key Components

### Database Schema
- **users**: User authentication table with id, username, and password
- **certificate_checks**: Stores certificate check results including hostname, port, status, expiration details, and error messages
- **Drizzle ORM**: Type-safe database operations with schema validation using Zod

### API Endpoints
- `GET /api/certificate-checks` - Retrieve all certificate checks
- `GET /api/certificate-checks/:hostname` - Get checks for specific hostname
- `POST /api/certificate-checks` - Perform new certificate check

### Frontend Components
- **CertificateTester**: Main component for inputting hostnames and triggering certificate checks
- **NSEScript**: Displays and allows copying of the Nmap NSE script
- **SyntaxHighlighter**: Custom syntax highlighting for Lua code
- **UI Components**: Comprehensive shadcn/ui component library

### Storage Layer
- **IStorage Interface**: Abstraction for data persistence
- **MemStorage**: In-memory storage implementation for development
- **Database Integration**: PostgreSQL with Drizzle ORM for production

## Data Flow

1. User enters hostname and optional port in the frontend form
2. Frontend sends POST request to `/api/certificate-checks`
3. Backend performs actual TLS certificate verification using Node.js `https` and `tls` modules
4. Certificate details are extracted (validity dates, issuer, subject, etc.)
5. Results are stored in the database and returned to the frontend
6. Frontend displays results with appropriate status indicators (valid, warning, expired, error)
7. Recent checks are displayed and automatically updated using React Query

## External Dependencies

### Frontend Dependencies
- **UI Components**: Radix UI primitives for accessible components
- **Styling**: Tailwind CSS with PostCSS for styling
- **Forms**: React Hook Form with Zod validation
- **Date Handling**: date-fns for date manipulation
- **Icons**: Lucide React for consistent iconography

### Backend Dependencies
- **Database**: Neon Database serverless PostgreSQL
- **ORM**: Drizzle ORM with PostgreSQL dialect
- **Validation**: Zod for runtime type checking
- **Session**: Connect-pg-simple for PostgreSQL session storage

## Deployment Strategy

### Build Process
- **Frontend**: Vite builds optimized static assets to `dist/public`
- **Backend**: esbuild compiles TypeScript server code to `dist/index.js`
- **Database**: Drizzle migrations stored in `./migrations` directory

### Environment Configuration
- **DATABASE_URL**: PostgreSQL connection string (required)
- **NODE_ENV**: Environment mode (development/production)
- **Sessions**: PostgreSQL-backed session storage

### Development vs Production
- **Development**: Uses Vite dev server with HMR, in-memory storage fallback
- **Production**: Serves static files from Express, uses PostgreSQL for persistence
- **Database**: Drizzle migrations for schema management

### Key Architectural Decisions

1. **Monorepo Structure**: Single repository with shared types and schemas between frontend and backend
2. **Type Safety**: End-to-end TypeScript with shared schema definitions
3. **Real-time Updates**: React Query for automatic cache invalidation and updates
4. **Flexible Storage**: Storage abstraction allows for different persistence strategies
5. **Modern Tooling**: Vite for fast development, esbuild for optimized production builds
6. **Component Architecture**: Modular UI components with consistent design system