/**
 * Calculator MCP Server Example
 *
 * A stateless calculator demonstrating:
 * - Basic math operations
 * - Advanced functions
 * - Unit conversions
 */

import { z } from "zod";
import { mcp } from "../src";
import { cors } from "../src/cors";

const app = mcp({
	name: "calculator",
	version: "1.0.0",
	instructions: `A calculator server with math operations and unit conversions.

Tools:
- add, subtract, multiply, divide: Basic arithmetic
- power, sqrt, abs: Advanced math
- sin, cos, tan: Trigonometry (input in degrees)
- log, ln: Logarithms
- factorial: Factorial calculation
- convert_temperature: Convert between Celsius, Fahrenheit, Kelvin
- convert_length: Convert between meters, feet, inches, etc.
- calculate: Evaluate a math expression`,
});

app.use(cors());

// Basic arithmetic
app.tool("add", {
	description: "Add two numbers",
	input: z.object({
		a: z.number().describe("First number"),
		b: z.number().describe("Second number"),
	}),
	handler: async ({ a, b }) => ({ result: a + b, expression: `${a} + ${b}` }),
});

app.tool("subtract", {
	description: "Subtract two numbers",
	input: z.object({
		a: z.number().describe("First number"),
		b: z.number().describe("Second number"),
	}),
	handler: async ({ a, b }) => ({ result: a - b, expression: `${a} - ${b}` }),
});

app.tool("multiply", {
	description: "Multiply two numbers",
	input: z.object({
		a: z.number().describe("First number"),
		b: z.number().describe("Second number"),
	}),
	handler: async ({ a, b }) => ({ result: a * b, expression: `${a} × ${b}` }),
});

app.tool("divide", {
	description: "Divide two numbers",
	input: z.object({
		a: z.number().describe("Dividend"),
		b: z.number().describe("Divisor"),
	}),
	handler: async ({ a, b }) => {
		if (b === 0) {
			return { error: "Division by zero" };
		}
		return { result: a / b, expression: `${a} ÷ ${b}` };
	},
});

// Advanced math
app.tool("power", {
	description: "Raise a number to a power",
	input: z.object({
		base: z.number().describe("Base number"),
		exponent: z.number().describe("Exponent"),
	}),
	handler: async ({ base, exponent }) => ({
		result: Math.pow(base, exponent),
		expression: `${base}^${exponent}`,
	}),
});

app.tool("sqrt", {
	description: "Calculate square root",
	input: z.object({
		n: z.number().describe("Number"),
	}),
	handler: async ({ n }) => {
		if (n < 0) {
			return { error: "Cannot calculate square root of negative number" };
		}
		return { result: Math.sqrt(n), expression: `√${n}` };
	},
});

app.tool("abs", {
	description: "Calculate absolute value",
	input: z.object({
		n: z.number().describe("Number"),
	}),
	handler: async ({ n }) => ({ result: Math.abs(n), expression: `|${n}|` }),
});

// Trigonometry (degrees)
app.tool("sin", {
	description: "Calculate sine (input in degrees)",
	input: z.object({
		degrees: z.number().describe("Angle in degrees"),
	}),
	handler: async ({ degrees }) => ({
		result: Math.sin((degrees * Math.PI) / 180),
		expression: `sin(${degrees}°)`,
	}),
});

app.tool("cos", {
	description: "Calculate cosine (input in degrees)",
	input: z.object({
		degrees: z.number().describe("Angle in degrees"),
	}),
	handler: async ({ degrees }) => ({
		result: Math.cos((degrees * Math.PI) / 180),
		expression: `cos(${degrees}°)`,
	}),
});

app.tool("tan", {
	description: "Calculate tangent (input in degrees)",
	input: z.object({
		degrees: z.number().describe("Angle in degrees"),
	}),
	handler: async ({ degrees }) => ({
		result: Math.tan((degrees * Math.PI) / 180),
		expression: `tan(${degrees}°)`,
	}),
});

// Logarithms
app.tool("log", {
	description: "Calculate base-10 logarithm",
	input: z.object({
		n: z.number().positive().describe("Positive number"),
	}),
	handler: async ({ n }) => ({
		result: Math.log10(n),
		expression: `log₁₀(${n})`,
	}),
});

app.tool("ln", {
	description: "Calculate natural logarithm",
	input: z.object({
		n: z.number().positive().describe("Positive number"),
	}),
	handler: async ({ n }) => ({
		result: Math.log(n),
		expression: `ln(${n})`,
	}),
});

// Factorial
app.tool("factorial", {
	description: "Calculate factorial",
	input: z.object({
		n: z.number().int().min(0).max(170).describe("Non-negative integer (max 170)"),
	}),
	handler: async ({ n }) => {
		let result = 1;
		for (let i = 2; i <= n; i++) {
			result *= i;
		}
		return { result, expression: `${n}!` };
	},
});

// Temperature conversion
app.tool("convert_temperature", {
	description: "Convert between temperature units",
	input: z.object({
		value: z.number().describe("Temperature value"),
		from: z.enum(["celsius", "fahrenheit", "kelvin"]).describe("Source unit"),
		to: z.enum(["celsius", "fahrenheit", "kelvin"]).describe("Target unit"),
	}),
	handler: async ({ value, from, to }) => {
		// Convert to Celsius first
		let celsius: number = value;
		if (from === "fahrenheit") {
			celsius = (value - 32) * (5 / 9);
		} else if (from === "kelvin") {
			celsius = value - 273.15;
		}

		// Convert from Celsius to target
		let result: number = celsius;
		if (to === "fahrenheit") {
			result = celsius * (9 / 5) + 32;
		} else if (to === "kelvin") {
			result = celsius + 273.15;
		}

		return {
			result: Math.round(result * 100) / 100,
			expression: `${value}°${from[0]!.toUpperCase()} → ${to}`,
		};
	},
});

// Length conversion
const lengthUnits: Record<string, number> = {
	meter: 1,
	kilometer: 1000,
	centimeter: 0.01,
	millimeter: 0.001,
	mile: 1609.34,
	yard: 0.9144,
	foot: 0.3048,
	inch: 0.0254,
};

app.tool("convert_length", {
	description: "Convert between length units",
	input: z.object({
		value: z.number().describe("Length value"),
		from: z
			.enum(["meter", "kilometer", "centimeter", "millimeter", "mile", "yard", "foot", "inch"])
			.describe("Source unit"),
		to: z
			.enum(["meter", "kilometer", "centimeter", "millimeter", "mile", "yard", "foot", "inch"])
			.describe("Target unit"),
	}),
	handler: async ({ value, from, to }) => {
		const meters = value * lengthUnits[from]!;
		const result = meters / lengthUnits[to]!;
		return {
			result: Math.round(result * 10000) / 10000,
			expression: `${value} ${from} → ${to}`,
		};
	},
});

// Constants
app.tool("constants", {
	description: "Get mathematical constants",
	handler: async () => ({
		pi: Math.PI,
		e: Math.E,
		sqrt2: Math.SQRT2,
		ln2: Math.LN2,
		ln10: Math.LN10,
	}),
});

app.listen(3000);
console.log("Calculator MCP server running on http://localhost:3000/mcp");

