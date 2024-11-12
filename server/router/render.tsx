import type { Context } from 'hono'
import type { FC } from 'hono/jsx'

const Layout: FC = (props) => {
    return (
        <html>
            <head>
                <title>Login</title>
                <style>
                    {`
                        body {
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            height: 100vh;
                            margin: 0;
                        }
                        form {
                            display: flex;
                            flex-direction: column;
                            width: 200px;
                            scale: 1.5;
                        }
                        input {
                            margin-bottom: 10px;
                        }
                    `}
                </style>
            </head>
            <body>{props.children}</body>
        </html>
    )
}

const Login: FC<{ 
    client_id: string,
    redirect_uri: string,
    response_type: string,
    scope: string,
    state: string
}> = (
    props: {
        client_id: string,
        redirect_uri: string,
        response_type: string,
        scope: string,
        state: string
    }
) => {
    return (
        <Layout>
            <form method="post" action="/oidc/authorize">
                <input type="hidden" name="client_id" value={props.client_id} />
                <input type="hidden" name="redirect_uri" value={props.redirect_uri} />
                <input type="hidden" name="response_type" value={props.response_type} />
                <input type="hidden" name="scope" value={props.scope} />
                <input type="hidden" name="state" value={props.state} />
                <input type="text" name="email" placeholder="Email" />
                <input type="password" name="password" placeholder="Password" />
                <button type="submit">Login</button>
            </form>
        </Layout>
    )
}

export const LoginPageController = async (ctx: Context) => {
    const {
        client_id,
        redirect_uri,
        response_type,
        scope,
        state
    } = ctx.req.query();

    if (!client_id || !redirect_uri || !response_type || !scope) {
        return ctx.json({
            error: "invalid_request",
            error_description: "Missing required parameters"
        }, 400)
    }

    return ctx.html(
        <Login
            client_id={client_id}
            redirect_uri={redirect_uri}
            response_type={response_type}
            scope={scope}
            state={state}
        />
    )
}