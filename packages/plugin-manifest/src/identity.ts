import { z } from "zod";

export const IDENTITY_TOKEN_MAX_AGE_SECONDS = 300;

/** Claims of the identity JWT Futurity sends in `Authorization` on every call. */
export const FuturityIdentityClaimsSchema = z
  .object({
    iss: z.string().min(1),
    aud: z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]),
    sub: z.string().min(1),
    org_id: z.string().min(1),
    holder: z.enum(["org", "user", "plugin", "none"]),
    credential_option: z.string().min(1),
    exp: z.number().int(),
    iat: z.number().int(),
    jti: z.string().min(1),
  })
  .refine((claims) => claims.exp > claims.iat && claims.exp - claims.iat <= IDENTITY_TOKEN_MAX_AGE_SECONDS, {
    message: `exp must be after iat and at most ${IDENTITY_TOKEN_MAX_AGE_SECONDS} seconds later`,
    path: ["exp"],
  });

export type FuturityIdentityClaims = z.infer<typeof FuturityIdentityClaimsSchema>;
