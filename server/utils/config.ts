import { z } from "zod";

declare global {
    // eslint-disable-next-line @typescript-eslint/no-namespace
    namespace NodeJS {
        // eslint-disable-next-line @typescript-eslint/no-empty-interface, @typescript-eslint/no-empty-object-type
        interface ProcessEnv extends z.infer<typeof ZodEnvironmentVariables> {}
    }
}


const ZodEnvironmentVariables = z.object({
    BASE_URL: z.string(),
});

export const Config = ZodEnvironmentVariables.parse(process.env);