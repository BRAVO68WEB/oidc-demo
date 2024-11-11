import { Hono } from "hono";
import { DBInit } from "./db";
import router from "./router";
import { showRoutes } from "hono/dev";

const app = new Hono();

DBInit();

app.get("/", async (ctx) => {
    return ctx.json({
        message: "Hello, World!"
    })
});

app.route("/", router);

showRoutes(app);

export default {
    port: 4000,
    fetch: app.fetch,
};