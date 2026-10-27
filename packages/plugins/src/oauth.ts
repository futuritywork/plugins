import { z } from "zod";

export const OAuthOptionsSchema = z.object({
	issuer: z.url(),
	authorizationEndpoint: z.url(),
	tokenEndpoint: z.url(),
	jwksUri: z.url().optional(),
	scopesSupported: z.array(z.string()).default([]).optional(),
	responseTypesSupported: z.array(z.string()).default(["code"]).optional(),
	grantTypesSupported: z
		.array(z.string())
		.default(["authorization_code"])
		.optional(),
	tokenEndpointAuthMethodsSupported: z.array(z.string()).optional(),
	registrationEndpoint: z.url().optional(),
	userInfoEndpoint: z.url().optional(),
});

export type OAuthOptions = z.infer<typeof OAuthOptionsSchema>;
