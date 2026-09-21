import { z } from "zod";

export const t = {
	str: z.string(),
	num: z.number(),
	bool: z.boolean(),
	obj: <T extends z.ZodRawShape>(shape: T) => z.object(shape),
	arr: <T>(inner: z.ZodType<T>) => z.array(inner),
};
