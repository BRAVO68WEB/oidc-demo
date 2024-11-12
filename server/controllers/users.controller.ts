import type { Context } from "hono";

import crypto from "node:crypto";
import { v4 as uuid } from "uuid";
import { db } from "../db";

export class Users {
    public static readonly CreateUser = async (ctx: Context) => {
        const { first_name, last_name, email, password, avatar_url } = await ctx.req.json()

        if (!first_name || !last_name || !email || !password) {
            return ctx.json({
                error: "invalid_request",
                error_description: "Missing required parameters"
            }, 400)
        }

        const id = uuid();
        const passwordHash = crypto
            .createHash("sha256")
            .update(password)
            .digest("hex")
        const created_at = new Date().toISOString();

        const stmt = db.prepare(`
            INSERT INTO users (id, first_name, last_name, email, password, avatar_url, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `)

        stmt.run(id, first_name, last_name, email, passwordHash, avatar_url, created_at, created_at)

        return ctx.json({
            id
        })
    }

    public static readonly GetUsers = async (ctx: Context) => {
        const users = db.prepare("SELECT * FROM users").all();

        return ctx.json(users)
    }

    public static readonly GetUser = async (ctx: Context) => {
        const user = db.prepare("SELECT * FROM users WHERE id = ?").get(ctx.req.param('id'));

        if (!user) {
            return ctx.json({
                error: "not_found",
                error_description: "User not found"
            }, 404)
        }

        return ctx.json(user)
    }

    public static readonly UpdateUser = async (ctx: Context) => {
        const { first_name, last_name, email, password, avatar_url } = await ctx.req.json()

        if (!first_name || !last_name || !email || !password) {
            return ctx.json({
                error: "invalid_request",
                error_description: "Missing required parameters"
            }, 400)
        }

        const user = db
            .prepare("SELECT * FROM users WHERE id = ?")
            .get(ctx.req.param('id')) as {
                id: string,
                first_name: string,
                last_name: string,
                email: string,
                password: string,
                avatar_url: string,
                created_at: string,
                updated_at: string
            }

        if (!user) {
            return ctx.json({
                error: "not_found",
                error_description: "User not found"
            }, 404)
        }

        const passwordHash = crypto
            .createHash("sha256")
            .update(password)
            .digest("hex")

        db.prepare("UPDATE users SET first_name = ?, last_name = ?, email = ?, password = ?, avatar_url = ?, updated_at = ? WHERE id = ?").run(first_name, last_name, email, passwordHash, avatar_url, new Date().toISOString(), user.id)

        return ctx.json({
            success: true
        })
    }

    public static readonly DeleteUser = async (ctx: Context) => {
        const user = db.prepare("SELECT * FROM users WHERE id = ?").get(ctx.req.param('id')) as {
            id: string,
        };
    
        if (!user) {
            return ctx.json({
                error: "not_found",
                error_description: "User not found"
            }, 404)
        }
    
        db.prepare("DELETE FROM users WHERE id = ?").run(user.id)
    
        return ctx.json({
            success: true
        })
    }
}