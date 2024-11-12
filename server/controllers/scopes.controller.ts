import type { Context } from "hono";

import { v4 as uuid } from "uuid";
import { db } from "../db";

export class Scopes {
    public static readonly GetScopes = async (ctx: Context) => {
        const scopes = db.prepare("SELECT * FROM scopes WHERE client_id = ?").all(ctx.req.param('client_id'));

        return ctx.json(scopes)
    }

    public static readonly CreateScope = async (ctx: Context) => {
        const { name } = await ctx.req.json()

        if (!name) {
            return ctx.json({
                error: "invalid_request",
                error_description: "Missing required parameters"
            }, 400)
        }

        const id = uuid();
        const created_at = new Date().toISOString();

        const stmt = db.prepare(`
            INSERT INTO scopes (id, name, client_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
        `)

        stmt.run(id, name, ctx.req.param('client_id'), created_at, created_at)

        return ctx.json({
            id
        })
    }

    public static readonly DeleteScope = async (ctx: Context) => {
        const scope = db.prepare("SELECT * FROM scopes WHERE id = ?").get(ctx.req.param('id')) as {
            id: string,
        };
    
        if (!scope) {
            return ctx.json({
                error: "not_found",
                error_description: "Scope not found"
            }, 404)
        }
    
        db.prepare("DELETE FROM scopes WHERE id = ?").run(scope.id)
    
        return ctx.json({
            success: true
        })
    }
}