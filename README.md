# Watchers Eye

Full-stack wallet viewer with user authentication, personal profiles, and gas-fee balance management (SQLite).

## Features

- **User Authentication**: Secure signup/login with email and password
- **Personal Profiles**: Each user gets a unique UID and profile
- **Wallet Management**: Track both home balance and gas fee balance
- **Transaction History**: View deposits, withdrawals, and on-chain transactions
- **Admin Panel**: Manual deposit management for administrators

## Local Development

```bash
npm install
ADMIN_KEY=1738 PORT=3001 npm start
# open http://localhost:3001
```

## Deploy on Render

- **Root Directory**: /
- **Build Command**: `npm install`
- **Start Command**: `npm start`
- **Environment Variables**: 
  - `ADMIN_KEY=1738` (for admin operations)
  - `PORT` (provided by Render)

## Database Schema

### Users Table
- `uid` (TEXT PRIMARY KEY): Unique user identifier
- `email` (TEXT UNIQUE): User email address
- `name` (TEXT): Wallet name
- `created_at` (INTEGER): Registration timestamp

### User Authentication Table
- `uid` (TEXT PRIMARY KEY): Links to users table
- `email` (TEXT UNIQUE): User email
- `password_hash` (TEXT): SHA-256 hashed password
- `created_at` (INTEGER): Account creation timestamp

### Balances Table
- `uid` (TEXT PRIMARY KEY): Links to users table
- `balance_usd` (REAL): Gas fee balance in USD
- `wallet_balance_usd` (REAL): Main wallet balance in USD
- `updated_at` (INTEGER): Last update timestamp

### Deposits Table
- `id` (INTEGER PRIMARY KEY): Transaction ID
- `uid` (TEXT): Links to users table
- `amount_usd` (REAL): Transaction amount (positive for deposits, negative for withdrawals)
- `note` (TEXT): Transaction description
- `created_at` (INTEGER): Transaction timestamp

## API Endpoints

### Authentication
- `POST /api/signup` - Create new user account
  - Body: `{ email, name, password }`
  - Returns: `{ ok: true, profile }`

- `POST /api/login` - Authenticate user
  - Body: `{ email, password }`
  - Returns: `{ ok: true, profile }`

### User Management
- `POST /api/register` - Legacy endpoint for compatibility
- `GET /api/profile/:uid` - Get user profile and balances
- `GET /api/users` - List all users (admin only, requires `x-admin-key` header)

### Transactions
- `POST /api/deposits/manual` - Manual deposit to gas fee balance (admin only)
- `POST /api/deposits/manual/home` - Manual deposit to home balance (admin only)
- `GET /api/deposits/:uid` - Get user's transaction history
- `POST /api/withdraw` - Process withdrawal from both balances

## Pages

- **login.html**: User authentication (entry page)
- **signup.html**: Create new user account
- **home.html**: Main wallet dashboard with balance and transactions
- **database.html**: Account details and gas fee balance
- **admin.html**: Admin panel for manual deposits (works cross-origin)
- **send.html**: Send/withdraw funds
- **deposit.html**: Deposit funds

## BscScan API Key (Optional)

For enhanced on-chain data, you can store a BscScan API key in the browser:

```javascript
localStorage.setItem('we_bscscan_key', 'YOUR_BSCSCAN_API_KEY');
```

This will be automatically appended to BscScan API requests to avoid rate limits.

## Default Balances

Every new user automatically receives:
- **Home Balance**: $200,915 USD (default allocation)
- **Gas Fee Balance**: $0 USD (starts empty)

## Security Features

- Passwords are hashed using SHA-256
- Email addresses are unique per account
- Admin operations require `x-admin-key` header
- Session management via localStorage
- Input validation on all endpoints

## Testing

Run the authentication test:

```bash
node test_auth.js
```

This will test signup, login, profile retrieval, and error handling.


