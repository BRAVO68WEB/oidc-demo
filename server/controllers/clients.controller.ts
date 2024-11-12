import type { Context } from "hono";

import crypto from "node:crypto";
import { v4 as uuid } from "uuid";
import { db } from "../db";

export class Clients {
    public static readonly CreateClients = async (ctx: Context) => {
        const { name, redirect_uri } = await ctx.req.json()

        if (!name || !redirect_uri) {
            return ctx.json({
                error: "invalid_request",
                error_description: "Missing required parameters"
            }, 400)
        }

        const id = uuid();
        const secret = crypto.randomBytes(32).toString("hex");
        const created_at = new Date().toISOString();

        const stmt = db.prepare(`
            INSERT INTO clients (id, name, secret, redirect_uri, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        `)

        stmt.run(id, name, secret, redirect_uri, created_at, created_at)

        // three default scopes
        db.prepare(`
            INSERT INTO scopes (id, name, client_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
        `).run(uuid(), "openid", id, created_at, created_at)
        db.prepare(`
            INSERT INTO scopes (id, name, client_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
        `).run(uuid(), "profile", id, created_at, created_at)
        db.prepare(`
            INSERT INTO scopes (id, name, client_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
        `).run(uuid(), "email", id, created_at, created_at)

        return ctx.json({
            id,
            secret
        })
    }

    public static readonly GetClients = async (ctx: Context) => {
        const clients = db.prepare("SELECT * FROM clients").all();

        return ctx.json(clients)
    }

    public static readonly GetClient = async (ctx: Context) => {
        const client = db.prepare("SELECT * FROM clients WHERE id = ?").get(ctx.req.param('id'));

        if (!client) {
            return ctx.json({
                error: "not_found",
                error_description: "Client not found"
            }, 404)
        }

        return ctx.json(client)
    }

    public static readonly UpdateClient = async (ctx: Context) => {
        const { name, redirect_uri } = await ctx.req.json()

        if (!name || !redirect_uri) {
            return ctx.json({
                error: "invalid_request",
                error_description: "Missing required parameters"
            }, 400)
        }

        const client = db
            .prepare("SELECT * FROM clients WHERE id = ?")
            .get(ctx.req.param('id')) as {
                id: string,
                name: string,
                secret: string,
                redirect_uri: string,
                created_at: string,
                updated_at: string
            }

        if (!client) {
            return ctx.json({
                error: "not_found",
                error_description: "Client not found"
            }, 404)
        }

        db.prepare("UPDATE clients SET name = ?, redirect_uri = ?, updated_at = ? WHERE id = ?").run(name, redirect_uri, new Date().toISOString(), client.id)

        return ctx.json({
            success: true
        })
    }

    public static readonly DeleteClient = async (ctx: Context) => {
        const client = db.prepare("SELECT * FROM clients WHERE id = ?").get(ctx.req.param('id')) as {
            id: string,
        };
    
        if (!client) {
            return ctx.json({
                error: "not_found",
                error_description: "Client not found"
            }, 404)
        }
    
        db.prepare("DELETE FROM clients WHERE id = ?").run(client.id)

        // delete all scopes
        db.prepare("DELETE FROM scopes WHERE client_id = ?").run(client.id)
    
        return ctx.json({
            success: true
        })
    }
}