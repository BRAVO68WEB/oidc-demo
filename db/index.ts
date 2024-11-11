import {
    Database
} from "bun:sqlite"

export const db = new Database("db.sqlite", {
    create: true
})

// Database to store OIDC users
export async function DBInit() {
    // Store Users
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id text PRIMARY KEY,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            avatar_url TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    `)

    // Store Clients
    db.exec(`
        CREATE TABLE IF NOT EXISTS clients (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            secret TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    `)

    // Store Sessions
    db.exec(`
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            refresh_token TEXT NOT NULL,
            scopes TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    `)

    // Store scopes
    db.exec(`
        CREATE TABLE IF NOT EXISTS scopes (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            client_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    `)

    // Store authorization codes
    db.exec(`
        CREATE TABLE IF NOT EXISTS authorization_codes (
            id TEXT PRIMARY KEY,
            code TEXT NOT NULL,
            state TEXT,
            user_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            scopes TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    `)

    return db
}