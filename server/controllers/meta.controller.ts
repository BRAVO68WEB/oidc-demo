import type { Context } from "hono";

export class MetaController {
    public static readonly Health = (ctx: Context) => {
        return ctx.text("OK!");
    };

    public static readonly Version = (ctx: Context) => {
        return ctx.json({ version: "0.0.0" });
    };

    public static readonly NotFound = (ctx: Context) => {
        return ctx.text("Not Found!", 404);
    };

    public static readonly InternalServerError = (ctx: Context) => {
        return ctx.text("Internal Server Error!", 500);
    };

    public static readonly NotImplemented = (ctx: Context) => {
        return ctx.text("Not Implemented!", 501);
    };
}